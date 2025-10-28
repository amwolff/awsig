package awsig

import (
	"testing"
	"time"
)

func TestV2V4(t *testing.T) {
	newV2V4 := func(provider CredentialsProvider[exampleAuthData], now func() time.Time) verifier[VerifiedRequest[exampleAuthData]] {
		v2v4 := NewV2V4(provider, V4Config{
			Region:  testDefaultRegion,
			Service: testDefaultService,
		})
		v2v4.v2.now = now
		v2v4.v4.now = now
		return v2v4
	}
	testV2(t, newV2V4)
	testV4(t, newV2V4)
}
