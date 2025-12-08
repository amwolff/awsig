package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/amwolff/awsig"
)

func main() {
	addr := flag.String("addr", "localhost:8000", "address to listen on")
	accesses := flag.String("accesses", "0555b35654ad1656d804:h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==,NOPQRSTUVWXYZABCDEFG:nopqrstuvwxyzabcdefghijklmnabcdefghijklm,HIJKLMNOPQRSTUVWXYZA:opqrstuvwxyzabcdefghijklmnopqrstuvwxyzab", "comma-separated list of accessKeyID:secretAccessKey pairs")
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
		log:     log.With("source", "credentialsDB"),
		entries: entries,
	}
	handler := newServer(log.With("source", "s3"), db)

	log.Info("starting server", "addr", *addr)

	server := &http.Server{
		Addr:        *addr,
		Handler:     handler,
		ReadTimeout: time.Second,
		ErrorLog:    slog.NewLogLogger(log.With("source", "http").Handler(), slog.LevelError),
	}

	if err = server.ListenAndServe(); err != nil {
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
	log     *slog.Logger
	entries map[string]credentialsData
}

func (c *credentialsDB) Provide(ctx context.Context, accessKeyID string) (string, credentialsData, error) {
	if data, ok := c.entries[accessKeyID]; ok {
		return data.secretAccessKey, data, nil
	}
	c.log.DebugContext(ctx, "unknown credential", "Access Key ID", accessKeyID)
	return "", credentialsData{}, awsig.ErrInvalidAccessKeyID
}

type object struct {
	name    string
	created time.Time
	data    []byte
}

type bucket struct {
	name    string
	created time.Time
	objects []object
}

type resultOwner struct {
	ID string `xml:"ID"`
}

type service struct {
	log  *slog.Logger
	mux  *http.ServeMux
	v2v4 *awsig.V2V4[credentialsData]

	vhost string

	data map[string]bucket
}

func newServer(log *slog.Logger, db *credentialsDB) *service {
	v2v4 := awsig.NewV2V4(db, awsig.V4Config{
		Service:                "s3",
		SkipRegionVerification: true,
	})

	svc := &service{
		log:  log,
		v2v4: v2v4,
		data: make(map[string]bucket),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", svc.listBuckets)
	mux.HandleFunc("GET /{bucket}", svc.listObjectVersions)
	mux.HandleFunc("PUT /{bucket}", svc.createBucket)
	mux.HandleFunc("PUT /{bucket}/{object...}", svc.createObject)
	mux.HandleFunc("POST /{bucket}", svc.deleteObjects)
	mux.HandleFunc("DELETE /{bucket}", svc.deleteBucket)
	mux.HandleFunc("/", svc.notFound)
	svc.mux = mux

	return svc
}

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *service) listBuckets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	log := s.log.With("action", "ListBuckets", "headers", r.Header, "query", query)

	if len(query) > 0 {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	type (
		listAllMyBucketsResultBucket struct {
			CreationDate string `xml:"CreationDate"`
			Name         string `xml:"Name"`
		}
		listAllMyBucketsResult struct {
			XMLName xml.Name `xml:"ListAllMyBucketsResult"`
			Buckets struct {
				Bucket []listAllMyBucketsResultBucket `xml:"Bucket"`
			} `xml:"Buckets"`
			Owner resultOwner `xml:"Owner"`
		}
	)

	result := listAllMyBucketsResult{
		Owner: resultOwner{
			ID: vr.AuthData().accessKeyID,
		},
	}

	for _, bucket := range s.data {
		result.Buckets.Bucket = append(result.Buckets.Bucket, listAllMyBucketsResultBucket{
			CreationDate: bucket.created.UTC().Format("2006-01-02T15:04:05+00:00"),
			Name:         bucket.name,
		})
	}
	slices.SortFunc(result.Buckets.Bucket, func(a, b listAllMyBucketsResultBucket) int {
		return strings.Compare(a.Name, b.Name)
	})

	writeXML(ctx, log, w, result)
	log.InfoContext(ctx, "listed buckets", "count", len(result.Buckets.Bucket))
}

func (s *service) listObjectVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bckt := r.PathValue("bucket")
	query := r.URL.Query()

	log := s.log.With("action", "ListObjectVersions", "bucket", bckt, "headers", r.Header, "query", query)

	// not supported: delimiter
	// supported: encoding-type
	// not supported: key-marker
	// supported: max-keys
	// not supported: prefix
	// not supported: version-id-marker

	for v := range query {
		if !slices.Contains([]string{"versions", "encoding-type", "max-keys"}, v) {
			xmlHTTPErrorNotImplemented(ctx, s.log, w)
			return
		}
	}

	encodingType := query.Get("encoding-type")
	if encodingType != "" && encodingType != "url" {
		log.WarnContext(ctx, "invalid encoding-type parameter", "value", encodingType)
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidArgument", "Invalid Encoding Method specified in Request")
		return
	}

	rawMaxKeys := query.Get("max-keys")
	maxKeys, err := strconv.Atoi(rawMaxKeys)
	if err != nil {
		log.WarnContext(ctx, "invalid max-keys parameter", "value", rawMaxKeys)
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidArgument", "Provided max-keys not an integer or within integer range")
		return
	} else if maxKeys < 0 {
		log.WarnContext(ctx, "invalid max-keys parameter", "value", rawMaxKeys)
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidArgument", "max-keys cannot be negative")
		return
	} else if maxKeys < len(s.data[bckt].objects) {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	type (
		listVersionsResultVersion struct {
			Key          string      `xml:"Key"`
			VersionId    string      `xml:"VersionId"`
			IsLatest     bool        `xml:"IsLatest"`
			LastModified string      `xml:"LastModified"`
			ETag         string      `xml:"ETag"`
			Size         int64       `xml:"Size"`
			Owner        resultOwner `xml:"Owner"`
			StorageClass string      `xml:"StorageClass"`
		}
		listVersionsResult struct {
			XMLName         xml.Name                    `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
			Name            string                      `xml:"Name"`
			Prefix          string                      `xml:"Prefix"`
			KeyMarker       string                      `xml:"KeyMarker"`
			VersionIdMarker string                      `xml:"VersionIdMarker"`
			MaxKeys         int                         `xml:"MaxKeys"`
			EncodingType    string                      `xml:"EncodingType,omitempty"`
			IsTruncated     bool                        `xml:"IsTruncated"`
			Version         []listVersionsResultVersion `xml:"Version"`
		}
	)

	result := listVersionsResult{
		Name:         bckt,
		MaxKeys:      maxKeys,
		EncodingType: encodingType,
		IsTruncated:  false,
	}

	// TOOD(amwolff): validate bucket exists
	for _, o := range s.data[bckt].objects {
		result.Version = append(result.Version, listVersionsResultVersion{
			Key:          o.name,
			VersionId:    "null",
			IsLatest:     true,
			LastModified: o.created.UTC().Format("2006-01-02T15:04:05.000Z"),
			Size:         int64(len(o.data)),
			Owner: resultOwner{
				ID: vr.AuthData().accessKeyID,
			},
			StorageClass: "STANDARD",
		})
	}
	slices.SortFunc(result.Version, func(a, b listVersionsResultVersion) int {
		return strings.Compare(a.Key, b.Key)
	})

	writeXML(ctx, log, w, result)
	log.InfoContext(ctx, "listed object versions", "count", len(result.Version))
}

func (s *service) createBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bckt := r.PathValue("bucket")
	query := r.URL.Query()

	log := s.log.With("action", "CreateBucket", "bucket", bckt, "headers", r.Header, "query", query)

	if len(query) > 0 {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	rd, err := vr.Reader()
	if err != nil {
		log.WarnContext(ctx, "failed to get verified reader", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}

	b, err := io.ReadAll(rd)
	if err != nil {
		log.WarnContext(ctx, "failed to read CreateBucket data", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}

	log.DebugContext(ctx, "body should be a valid XML", "body", string(b))

	// TOOD(amwolff): validate bucket does not exist + name rules
	s.data[bckt] = bucket{
		name:    bckt,
		created: time.Now(),
	}

	log.InfoContext(ctx, "created bucket", "name", bckt)
}

func (s *service) createObject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bckt, name := r.PathValue("bucket"), r.PathValue("object")
	query := r.URL.Query()

	log := s.log.With("action", "PutObject", "bucket", bckt, "object", name, "headers", r.Header, "query", query)

	if len(query) > 0 {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	rawContentLength, ok := r.Header["Content-Length"]
	if !ok {
		log.WarnContext(ctx, "missing Content-Length header")
		xmlHTTPError(ctx, log, w, http.StatusLengthRequired, "MissingContentLength", "You must provide the Content-Length HTTP header.")
		return
	}
	contentLength, err := strconv.ParseInt(rawContentLength[0], 10, 64)
	if err != nil || contentLength < 0 {
		log.WarnContext(ctx, "invalid Content-Length header", "value", rawContentLength[0])
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidArgument", "The specified argument was not valid.")
		return
	}

	rd, err := vr.Reader()
	if err != nil {
		log.WarnContext(ctx, "failed to get verified reader", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}

	b, err := io.ReadAll(rd)
	if err != nil {
		log.WarnContext(ctx, "failed to read object data", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}

	// TOOD(amwolff): validate bucket exists
	bucket := s.data[bckt]
	bucket.objects = append(bucket.objects, object{
		name:    name,
		created: time.Now(),
		data:    b,
	})
	s.data[bckt] = bucket

	log.InfoContext(ctx, "stored object", "name", name, "size", len(b), "bucket", bckt)
}

func (s *service) deleteObjects(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bckt := r.PathValue("bucket")
	query := r.URL.Query()

	log := s.log.With("action", "DeleteObjects", "bucket", bckt, "headers", r.Header, "query", query)

	if len(query) != 1 || !query.Has("delete") {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	type (
		deleteObject struct {
			ETag             string `xml:"ETag"`
			Key              string `xml:"Key"`
			LastModifiedTime string `xml:"LastModifiedTime"`
			Size             int64  `xml:"Size"`
			VersionId        string `xml:"VersionId"`
		}
		delete struct {
			XMLName xml.Name       `xml:"Delete"`
			Object  []deleteObject `xml:"Object"`
			Quiet   bool           `xml:"Quiet"`
		}
	)

	rd, err := vr.Reader()
	if err != nil {
		log.WarnContext(ctx, "failed to get verified reader", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}

	var request delete
	if err := xml.NewDecoder(rd).Decode(&request); err != nil {
		log.WarnContext(ctx, "failed to decode delete request", "error", err)
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "MalformedXML", "The XML that you provided was not well formed or did not validate against our published schema.")
		return
	}

	if !request.Quiet {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	var deletable []string // not that atomicity matters here…
	for _, o := range request.Object {
		if o.ETag != "" || o.LastModifiedTime != "" || o.Size != 0 || (o.VersionId != "" && o.VersionId != "null") {
			xmlHTTPErrorNotImplemented(ctx, s.log, w)
			return
		}
		deletable = append(deletable, o.Key)
	}

	// TOOD(amwolff): validate bucket exists
	bucket := s.data[bckt]
	bucket.objects = slices.DeleteFunc(s.data[bckt].objects, func(o object) bool {
		return slices.Contains(deletable, o.name)
	})
	s.data[bckt] = bucket

	// no response body for Quiet mode…?
	log.InfoContext(ctx, "deleted objects", "count", len(request.Object))
}

func (s *service) deleteBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bckt := r.PathValue("bucket")
	query := r.URL.Query()

	log := s.log.With("action", "DeleteBucket", "bucket", bckt, "headers", r.Header, "query", query)

	if len(query) > 0 {
		xmlHTTPErrorNotImplemented(ctx, s.log, w)
		return
	}

	vr, err := s.v2v4.Verify(r, s.vhost)
	if err != nil {
		log.WarnContext(ctx, "failed to verify request", "error", err)
		awsigErrorToHTTPError(ctx, log, w, err)
		return
	}
	log = log.With("Access Key ID", vr.AuthData().accessKeyID)

	// TOOD(amwolff): validate bucket exists
	if len(s.data[bckt].objects) > 0 {
		log.WarnContext(ctx, "bucket not empty", "objects", len(s.data[bckt].objects))
		xmlHTTPError(ctx, log, w, http.StatusConflict, "BucketNotEmpty", "The bucket you tried to delete is not empty")
		return
	}

	delete(s.data, bckt)

	w.WriteHeader(http.StatusNoContent)
	log.InfoContext(ctx, "deleted bucket")
}

func (s *service) notFound(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.log.WarnContext(ctx, "not found", "method", r.Method, "url", r.URL.String(), "headers", r.Header)
	xmlHTTPErrorNotImplemented(ctx, s.log, w)
}

func writeXML(ctx context.Context, log *slog.Logger, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	e := xml.NewEncoder(w)
	if err := e.Encode(v); err != nil {
		log.ErrorContext(ctx, "failed to write XML response", "error", err)
	}
	if err := e.Close(); err != nil {
		log.ErrorContext(ctx, "failed to finalize XML response", "error", err)
	}
}

func xmlHTTPError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, statusCode int, code, message string) {
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

func awsigErrorToHTTPError(ctx context.Context, log *slog.Logger, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, awsig.ErrAuthorizationHeaderMalformed):
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "AuthorizationHeaderMalformed", "The authorization header that you provided is not valid.")
	case errors.Is(err, awsig.ErrInvalidAccessKeyID):
		xmlHTTPError(ctx, log, w, http.StatusForbidden, "InvalidAccessKeyId", "The AWS access key ID that you provided does not exist in our records.")
	case errors.Is(err, awsig.ErrInvalidArgument):
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidArgument", "Bad Request")
	case errors.Is(err, awsig.ErrInvalidRequest):
		xmlHTTPError(ctx, log, w, http.StatusBadRequest, "InvalidRequest", "Bad Request")
	case errors.Is(err, awsig.ErrMissingAuthenticationToken):
		xmlHTTPError(ctx, log, w, http.StatusForbidden, "MissingAuthenticationToken", "The request was not signed.")
	case errors.Is(err, awsig.ErrRequestTimeTooSkewed):
		xmlHTTPError(ctx, log, w, http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and the server's time is too large.")
	case errors.Is(err, awsig.ErrSignatureDoesNotMatch):
		xmlHTTPError(ctx, log, w, http.StatusForbidden, "SignatureDoesNotMatch", "The request signature that the server calculated does not match the signature that you provided. Check your AWS secret access key and signing method. For more information, see REST Authentication and SOAP Authentication.")
	default:
		xmlHTTPError(ctx, log, w, http.StatusInternalServerError, "InternalError", "An internal error occurred. Try again.")
	}
}

func xmlHTTPErrorNotImplemented(ctx context.Context, log *slog.Logger, w http.ResponseWriter) {
	log.WarnContext(ctx, "not implemented")
	xmlHTTPError(ctx, log, w, http.StatusNotImplemented, "NotImplemented", "A header that you provided implies functionality that is not implemented.")
}
