package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/amwolff/awsig"
)

func main() {
	addr := flag.String("addr", "localhost:8000", "address to listen on")
	accesses := flag.String("accesses", "0555b35654ad1656d804:h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==", "comma-separated list of accessKeyID:secretAccessKey pairs")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}))

	entries, err := parseAccesses(*accesses)
	if err != nil {
		log.Error("fatal: failed to parse accesses", "error", err)
		return
	}

	log.Info("loaded accesses", "count", len(entries))

	db := &credentialsDB{
		entries: entries,
	}
	handler := newServer(log.With("source", "s3"), db)

	log.Info("starting server", "addr", *addr)

	if err = http.ListenAndServe(*addr, handler); err != nil {
		log.Error("server error", "error", err)
	}
}

func parseAccesses(accesses string) (map[string]credentialsData, error) {
	splitAccesses := strings.Split(accesses, ",")

	entries := make(map[string]credentialsData)
	for _, access := range splitAccesses {
		parts := strings.SplitN(access, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid access format: %s", access)
		}

		accessKeyID := parts[0]

		entries[accessKeyID] = credentialsData{
			accessKeyID:     accessKeyID,
			secretAccessKey: parts[1],
		}
	}

	return entries, nil
}

type credentialsData struct {
	accessKeyID     string
	secretAccessKey string
}

type credentialsDB struct {
	entries map[string]credentialsData
}

func (c *credentialsDB) Provide(ctx context.Context, accessKeyID string) (string, credentialsData, error) {
	if data, ok := c.entries[accessKeyID]; ok {
		return data.secretAccessKey, data, nil
	}
	return "", credentialsData{}, awsig.ErrInvalidAccessKeyID
}

type object struct {
	name string
	data []byte
}

type service struct {
	log  *slog.Logger
	mux  *http.ServeMux
	v2v4 *awsig.V2V4[credentialsData]

	vhost string

	data map[string][]object
}

func newServer(log *slog.Logger, db *credentialsDB) *service {
	v2v4 := awsig.NewV2V4(db, awsig.V4Config{
		Service:                "s3",
		SkipRegionVerification: true,
	})

	svc := &service{
		log:  log,
		v2v4: v2v4,
		data: make(map[string][]object),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /{bucket}", svc.createBucket)
	mux.HandleFunc("PUT /{bucket}/{object...}", svc.createObject)
	mux.HandleFunc("/", svc.notFound)
	svc.mux = mux

	return svc
}

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *service) createBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bucket := r.PathValue("bucket")

	log := s.log.With("action", "CreateBucket", "bucket", bucket)

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	rd, err := vr.Reader()
	if err != nil {
		log.WarnContext(ctx, "failed to get verified reader", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}

	b, err := io.ReadAll(rd)
	if err != nil {
		log.WarnContext(ctx, "failed to read CreateBucket data", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}

	log.DebugContext(ctx, "body should be a valid XML", "body", string(b))

	// TOOD(amwolff): validate bucket does not exist + name rules
	s.data[bucket] = make([]object, 0)

	log.InfoContext(ctx, "created bucket", "name", bucket)
}

func (s *service) createObject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bucket, name := r.PathValue("bucket"), r.PathValue("object")

	log := s.log.With("action", "PutObject", "bucket", bucket, "object", name)

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	rd, err := vr.Reader()
	if err != nil {
		log.WarnContext(ctx, "failed to get verified reader", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}

	b, err := io.ReadAll(rd)
	if err != nil {
		log.WarnContext(ctx, "failed to read object data", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err, "")
		return
	}

	// TOOD(amwolff): validate bucket exists
	s.data[bucket] = append(s.data[bucket], object{
		name: name,
		data: b,
	})

	log.InfoContext(ctx, "stored object", "name", name, "size", len(b), "bucket", bucket)
}

func awsigErrorToHTTPError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, err error, resource string) {
	switch {
	default:
		xmlHTTPError(ctx, log, w, http.StatusInternalServerError, "InternalError", "An internal error occurred. Try again.", resource)
	}
}

func (s *service) notFound(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.log.WarnContext(ctx, "not found", "url", r.URL.String())
	xmlHTTPError(ctx, s.log, w, http.StatusBadRequest, "InvalidRequest", "Bad Request", "")
}

func xmlHTTPError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, statusCode int, code, message, resource string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/xml; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	var requestID [8]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		log.ErrorContext(ctx, "failed to generate request ID", "error", err)
	}

	v := struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource,omitempty"`
		RequestID string   `xml:"RequestId"`
		HostID    string   `xml:"HostId"`
	}{
		Code:      code,
		Message:   message,
		Resource:  resource,
		RequestID: strings.ToUpper(hex.EncodeToString(requestID[:])),
		HostID:    "awsig/s3-tests/server",
	}

	e := xml.NewEncoder(w)
	if err := e.Encode(v); err != nil {
		log.ErrorContext(ctx, "failed to write XML error response", "error", err)
	}
	if err := e.Close(); err != nil {
		log.ErrorContext(ctx, "failed to finalize XML error response", "error", err)
	}
}
