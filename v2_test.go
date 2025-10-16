package awsig

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestV2(t *testing.T) {
	newV2 := func(provider CredentialsProvider, now func() time.Time) verifier[*V2VerifiedRequest] {
		v2 := NewV2(provider)
		v2.now = now
		return v2
	}
	testV2(t, newV2)
}

func testV2[T VerifiedRequest](t *testing.T, newV2 func(CredentialsProvider, func() time.Time) verifier[T]) {
	const accessKeyID = "AKIAIOSFODNN7EXAMPLE"

	provider := simpleCredentialsProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	t.Run("Object GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/photos/puppy.jpg", nil)
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:qgk2+6Sv9/oM7G3qLEjTH1a1l1g=")

		v2 := newV2(provider, dummyNow(2007, time.March, 27, 19, 36, 42))

		vr, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Object PUT", func(t *testing.T) {
		body := make([]byte, 94328)

		_, err := io.ReadFull(rand.Reader, body)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/photos/puppy.jpg", bytes.NewBuffer(body))
		req.Header.Add("Content-Type", "image/jpeg")
		req.Header.Add("Content-Length", "94328")
		req.Header.Add("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:iqRzw+ileNPu1fhspnRs8nOjjIA=")

		v2 := newV2(provider, dummyNow(2007, time.March, 27, 21, 15, 45))

		vr, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		b, err := io.ReadAll(r)
		assert.NoError(t, err)
		assert.Equal(t, body, b)
	})
	t.Run("List", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/?prefix=photos&max-keys=50&marker=puppy", nil)
		req.Header.Add("User-Agent", "Mozilla/5.0")
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:42:41 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:m0WP8eCtspQl5Ahe6L1SozdX9YA=")

		v2 := newV2(provider, dummyNow(2007, time.March, 27, 19, 42, 41))

		vr, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Fetch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/?acl", nil)
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:44:46 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:82ZHiFIjc+WbcwFKGUVEQspPn+0=")

		v2 := newV2(provider, dummyNow(2007, time.March, 27, 19, 44, 46))

		vr, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Delete", func(t *testing.T) {
		// NOTE(amwolff): the "Delete" example from
		// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#RESTAuthenticationExamples
		// is contradictory to the spec…
		t.SkipNow()
	})
	t.Run("Upload", func(t *testing.T) {
		// NOTE(amwolff): the "Upload" example from
		// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#RESTAuthenticationExamples
		// doesn't say what the body is, so it's going to be hard to
		// reproduce the Content-MD5 header.
		t.SkipNow()
	})
	t.Run("List all my buckets", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://s3.us-west-1.amazonaws.com/", nil)
		req.Header.Add("Date", "Wed, 28 Mar 2007 01:29:59 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=")

		v2 := newV2(provider, dummyNow(2007, time.March, 28, 1, 29, 59))

		vr, err := v2.Verify(req, "")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Unicode keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://s3.us-west-1.amazonaws.com/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re", nil)
		req.Header.Add("Date", "Wed, 28 Mar 2007 01:49:49 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=")

		v2 := newV2(provider, dummyNow(2007, time.March, 28, 1, 49, 49))

		vr, err := v2.Verify(req, "")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})

	const accessKeyID2 = "44CF9590006BF252F707"

	provider2 := simpleCredentialsProvider{
		accessKeyID:     accessKeyID2,
		secretAccessKey: "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV",
	}

	t.Run("presigned 1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://s3.amazonaws.com/quotes/nelson?AWSAccessKeyId=44CF9590006BF252F707&Expires=1141889120&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D", nil)
		req.Header.Add("Date", "Thu, 09 Mar 2006 07:25:20 GMT")

		v2 := newV2(provider2, dummyNow(2006, time.March, 9, 7, 25, 20))

		vr, err := v2.Verify(req, "")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID2, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("presigned 2", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=NpgCjnDzrM%2BWFzoENXmpNDUsSn8%3D&Expires=1175139620", nil)

		v2 := newV2(provider, dummyNow(2007, time.March, 29, 3, 40, 19))

		vr, err := v2.Verify(req, "johnsmith")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("expired presigned 1", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://s3.amazonaws.com/quotes/nelson?AWSAccessKeyId=44CF9590006BF252F707&Expires=1141889120&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D", nil)
		req.Header.Add("Date", "Mon, 26 Mar 2007 19:37:58 +0000")

		v2 := newV2(provider2, dummyNow(2007, time.March, 26, 19, 37, 58))

		_, err := v2.Verify(req, "")
		assert.Error(t, err)
	})
	t.Run("expired presigned 2", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=NpgCjnDzrM%2BWFzoENXmpNDUsSn8%3D&Expires=1175139620", nil)

		v2 := newV2(provider, dummyNow(2007, time.March, 29, 3, 40, 21))

		_, err := v2.Verify(req, "johnsmith")
		assert.Error(t, err)
	})

	const accessKeyID3 = "AKIAIOSFODNN7EXAMPLE"

	provider3 := simpleCredentialsProvider{
		accessKeyID:     accessKeyID3,
		secretAccessKey: "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o",
	}

	t.Run("presigned (POST)", func(t *testing.T) {
		file := make([]byte, 117108)
		body := bytes.NewBuffer(nil)

		mw := multipart.NewWriter(body)

		assert.NoError(t, mw.SetBoundary("9431149156168"))

		assert.NoError(t, mw.WriteField("key", "user/eric/MyPicture.jpg"))
		assert.NoError(t, mw.WriteField("acl", "public-read"))
		assert.NoError(t, mw.WriteField("success_action_redirect", "http://johnsmith.s3.amazonaws.com/successful_upload.html"))
		assert.NoError(t, mw.WriteField("Content-Type", "image/jpeg"))
		assert.NoError(t, mw.WriteField("x-amz-meta-uuid", "14365123651274"))
		assert.NoError(t, mw.WriteField("x-amz-meta-tag", "Some,Tag,For,Picture"))
		assert.NoError(t, mw.WriteField("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE"))
		assert.NoError(t, mw.WriteField("Policy", "eyAiZXhwaXJhdGlvbiI6ICIyMDA3LTEyLTAxVDEyOjAwOjAwLjAwMFoiLAogICJjb25kaXRpb25zIjogWwogICAgeyJidWNrZXQiOiAiam9obnNtaXRoIn0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci9lcmljLyJdLAogICAgeyJhY2wiOiAicHVibGljLXJlYWQifSwKICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL2pvaG5zbWl0aC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwKICAgIFsic3RhcnRzLXdpdGgiLCAiJENvbnRlbnQtVHlwZSIsICJpbWFnZS8iXSwKICAgIHsieC1hbXotbWV0YS11dWlkIjogIjE0MzY1MTIzNjUxMjc0In0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiR4LWFtei1tZXRhLXRhZyIsICIiXQogIF0KfQo="))
		assert.NoError(t, mw.WriteField("Signature", "0RavWzkygo6QX9caELEqKi9kDbU="))

		partHeaders := make(textproto.MIMEHeader)
		partHeaders.Set("Content-Disposition", multipart.FileContentDisposition("file", "MyFilename.jpg"))
		partHeaders.Set("Content-Type", "image/jpeg")

		part, err := mw.CreatePart(partHeaders)
		assert.NoError(t, err)

		_, err = io.ReadFull(rand.Reader, file)
		assert.NoError(t, err)

		_, err = io.Copy(part, bytes.NewReader(file))
		assert.NoError(t, err)

		assert.NoError(t, mw.WriteField("submit", "Upload to Amazon S3"))

		assert.NoError(t, mw.Close())

		req := httptest.NewRequest(http.MethodPost, "http://johnsmith.s3.amazonaws.com/", body)
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.10) Gecko/20071115 Firefox/2.0.0.10")
		req.Header.Add("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
		req.Header.Add("Accept-Language", "en-us,en;q=0.5")
		req.Header.Add("Accept-Encoding", "gzip,deflate")
		req.Header.Add("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
		req.Header.Add("Keep-Alive", "300")
		req.Header.Add("Connection", "keep-alive")
		req.Header.Set("Content-Type", "multipart/form-data; boundary=9431149156168")
		req.Header.Add("Content-Length", strconv.Itoa(body.Len()))

		v2 := newV2(provider3, time.Now)

		vr, err := v2.Verify(req, "johnsmith")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID3, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		b, err := io.ReadAll(r)
		assert.NoError(t, err)
		assert.Equal(t, file, b)
	})
	t.Run("presigned (POST) 2", func(t *testing.T) {
		file := make([]byte, 117108)
		body := bytes.NewBuffer(nil)

		mw := multipart.NewWriter(body)

		assert.NoError(t, mw.SetBoundary("178521717625888"))

		assert.NoError(t, mw.WriteField("key", "user/eric/NewEntry.html"))
		assert.NoError(t, mw.WriteField("acl", "public-read"))
		assert.NoError(t, mw.WriteField("success_action_redirect", "http://johnsmith.s3.amazonaws.com/new_post.html"))
		assert.NoError(t, mw.WriteField("Content-Type", "text/html"))
		assert.NoError(t, mw.WriteField("x-amz-meta-uuid", "14365123651274"))
		assert.NoError(t, mw.WriteField("x-amz-meta-tag", "Interesting Post"))
		assert.NoError(t, mw.WriteField("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE"))
		assert.NoError(t, mw.WriteField("Policy", "eyAiZXhwaXJhdGlvbiI6ICIyMDA3LTEyLTAxVDEyOjAwOjAwLjAwMFoiLAogICJjb25kaXRpb25zIjogWwogICAgeyJidWNrZXQiOiAiam9obnNtaXRoIn0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci9lcmljLyJdLAogICAgeyJhY2wiOiAicHVibGljLXJlYWQifSwKICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL2pvaG5zbWl0aC5zMy5hbWF6b25hd3MuY29tL25ld19wb3N0Lmh0bWwifSwKICAgIFsiZXEiLCAiJENvbnRlbnQtVHlwZSIsICJ0ZXh0L2h0bWwiXSwKICAgIHsieC1hbXotbWV0YS11dWlkIjogIjE0MzY1MTIzNjUxMjc0In0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiR4LWFtei1tZXRhLXRhZyIsICIiXQogIF0KfQo="))
		assert.NoError(t, mw.WriteField("Signature", "qA7FWXKq6VvU68lI9KdveT1cWgF="))

		part, err := mw.CreateFormField("file")
		assert.NoError(t, err)

		_, err = io.ReadFull(rand.Reader, file)
		assert.NoError(t, err)

		_, err = io.Copy(part, bytes.NewReader(file))
		assert.NoError(t, err)

		assert.NoError(t, mw.WriteField("submit", "Upload to Amazon S3"))

		assert.NoError(t, mw.Close())

		req := httptest.NewRequest(http.MethodPost, "http://johnsmith.s3.amazonaws.com/", body)
		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.10) Gecko/20071115 Firefox/2.0.0.10")
		req.Header.Add("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
		req.Header.Add("Accept-Language", "en-us,en;q=0.5")
		req.Header.Add("Accept-Encoding", "gzip,deflate")
		req.Header.Add("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7")
		req.Header.Add("Keep-Alive", "300")
		req.Header.Add("Connection", "keep-alive")
		req.Header.Set("Content-Type", "multipart/form-data; boundary=178521717625888")
		req.Header.Add("Content-Length", strconv.Itoa(body.Len()))

		v2 := newV2(provider3, time.Now)

		vr, err := v2.Verify(req, "johnsmith")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID3, vr.AccessKeyID())

		r, err := vr.Reader()
		assert.NoError(t, err)

		b, err := io.ReadAll(r)
		assert.NoError(t, err)
		assert.Equal(t, file, b)
	})
}
