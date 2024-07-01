package httppeeridauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// TestMutualAuth tests that we can do a mutually authenticated round trip
func TestMutualAuth(t *testing.T) {
	logging.SetLogLevel("httppeeridauth", "DEBUG")

	zeroBytes := make([]byte, 64)
	serverKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))
	require.NoError(t, err)
	auth := PeerIDAuth{
		PrivKey:      serverKey,
		ValidOrigins: map[string]struct{}{"example.com": {}},
		TokenTTL:     time.Hour,
	}

	ts := httptest.NewServer(&auth)
	defer ts.Close()

	type testCase struct {
		name         string
		clientKeyGen func(t *testing.T) crypto.PrivKey
	}

	testCases := []testCase{
		{
			name: "ED25519",
			clientKeyGen: func(t *testing.T) crypto.PrivKey {
				clientKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
				require.NoError(t, err)
				return clientKey
			},
		},
		{
			name: "RSA",
			clientKeyGen: func(t *testing.T) crypto.PrivKey {
				clientKey, _, err := crypto.GenerateRSAKeyPair(2048, rand.Reader)
				require.NoError(t, err)
				return clientKey
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{}
			clientKey := tc.clientKeyGen(t)
			clientAuth := ClientPeerIDAuth{PrivKey: clientKey}

			expectedServerID, err := peer.IDFromPrivateKey(serverKey)
			require.NoError(t, err)

			ctx := context.Background()
			serverID, err := clientAuth.MutualAuth(ctx, client, ts.URL, "example.com")
			require.NoError(t, err)
			require.Equal(t, expectedServerID, serverID)
			require.NotZero(t, clientAuth.tokenMap["example.com"])

			// Once more with the auth token
			req, err := http.NewRequest("GET", ts.URL, nil)
			require.NoError(t, err)
			req.Host = "example.com"
			serverID, err = clientAuth.AddAuthTokenToRequest(req)
			require.NoError(t, err)
			require.Equal(t, expectedServerID, serverID)

			// Verify that unwrapping our token gives us the client's peer ID
			expectedClientPeerID, err := peer.IDFromPrivateKey(clientKey)
			require.NoError(t, err)
			clientPeerID, err := auth.UnwrapBearerToken(req)
			require.NoError(t, err)
			require.Equal(t, expectedClientPeerID, clientPeerID)

			// Verify that we can make an authenticated request
			resp, err := client.Do(req)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestParseAuthHeader(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected map[string]authScheme
		err      error
	}{
		{
			name:     "empty header",
			header:   "",
			expected: nil,
			err:      nil,
		},
		{
			name:     "header too long",
			header:   strings.Repeat("a", maxAuthHeaderSize+1),
			expected: nil,
			err:      fmt.Errorf("header too long"),
		},
		{
			name:     "too many schemes",
			header:   strings.Repeat("libp2p-Bearer token1, ", maxSchemes+1),
			expected: nil,
			err:      fmt.Errorf("too many schemes"),
		},
		{
			name:     "Valid Bearer scheme",
			header:   "libp2p-Bearer token123",
			expected: map[string]authScheme{"libp2p-Bearer": {bearerToken: "token123", scheme: "libp2p-Bearer"}},
			err:      nil,
		},
		{
			name:     "Valid PeerID scheme",
			header:   "libp2p-PeerID param1=val1, param2=val2",
			expected: map[string]authScheme{"libp2p-PeerID": {scheme: "libp2p-PeerID", params: map[string]string{"param1": "val1", "param2": "val2"}}},
			err:      nil,
		},
		{
			name:   "Ignore unknown scheme",
			header: "Unknown scheme1, libp2p-Bearer token456, libp2p-PeerID param=value",
			expected: map[string]authScheme{
				"libp2p-Bearer": {
					scheme:      "libp2p-Bearer",
					bearerToken: "token456"},
				"libp2p-PeerID": {scheme: "libp2p-PeerID", params: map[string]string{"param": "value"}}},
			err: nil,
		},
		{
			name:   "Parse quoted params",
			header: `libp2p-PeerID param="value"`,
			expected: map[string]authScheme{
				"libp2p-PeerID": {scheme: "libp2p-PeerID", params: map[string]string{"param": "value"}}},
			err: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := parseAuthHeader(tc.header)
			if tc.err != nil {
				require.Error(t, err, tc.err)
				require.Equal(t, tc.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, actual)
			}
		})
	}
}

func FuzzParseAuthHeader(f *testing.F) {
	// Just check that we don't panic'
	f.Fuzz(func(t *testing.T, data []byte) {
		parseAuthHeader(string(data))
	})
}

func FuzzServeHTTP(f *testing.F) {
	zeroBytes := make([]byte, 64)
	serverKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))
	require.NoError(f, err)
	auth := PeerIDAuth{
		PrivKey:      serverKey,
		ValidOrigins: map[string]struct{}{"example.com": {}},
		TokenTTL:     time.Hour,
	}
	// Just check that we don't panic'
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		hostLen := int(data[0])
		data = data[1:]
		if hostLen > len(data) {
			return
		}
		host := string(data[:hostLen])
		data = data[hostLen:]
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Host = host
		req.Header.Set("Authorization", string(data))
		auth.ServeHTTP(httptest.NewRecorder(), req)
	})
}

func BenchmarkAuths(b *testing.B) {
	zeroBytes := make([]byte, 64)
	serverKey, _, err := crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))
	require.NoError(b, err)
	auth := PeerIDAuth{
		PrivKey:      serverKey,
		ValidOrigins: map[string]struct{}{"example.com": {}},
		TokenTTL:     time.Hour,
	}

	ts := httptest.NewServer(&auth)
	defer ts.Close()

	ctx := context.Background()
	client := &http.Client{}
	clientKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(b, err)
	clientAuth := ClientPeerIDAuth{PrivKey: clientKey}
	clientID, err := peer.IDFromPrivateKey(clientKey)
	require.NoError(b, err)
	challengeServer := make([]byte, challengeLen)
	clientAuthValue, err := clientAuth.authSelfToServer(ctx, client, clientID, challengeServer, ts.URL, "example.com")
	require.NoError(b, err)

	b.ResetTimer()
	req, err := http.NewRequest("GET", ts.URL, nil)
	require.NoError(b, err)
	req.Host = "example.com"
	req.Header.Set("Authorization", clientAuthValue)

	for i := 0; i < b.N; i++ {
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			b.Fatal(err, resp.StatusCode)
		}
	}
}

// Test Vectors
var zeroBytes = make([]byte, 64)
var zeroKey, _, _ = crypto.GenerateEd25519Key(bytes.NewReader(zeroBytes))

// Peer ID derived from the zero key
var zeroID, _ = peer.IDFromPublicKey(zeroKey.GetPublic())

// Result of signing with a zero key and a 32 0 byte challenge with origin "example.com"
var expectedClientSig = `56975c7694351cca10bf1c84fee1d49df86b6e356d8ff3208080b9cb49098d1e437845d87aacd15f908aabc8031ddc769721bb6bb9e4d1f2d2fc85b6d3c99e07`

// Result of signing with a zero key and a 32 0 byte challenge with origin
// "example.com" and client ID derived from the zero key
var expectedServerSig = `4bc1ac4653cb2fa816b10793c2597da7bb4ab1391cd5e75332b96482a216f9cda197dcfb92727dbbacee9ad6859f3dc9edea5ab43fe6abbfa49c095efaeaa60e`

type inputToSigning struct {
	prefix string
	params map[string]string
}

// 32 0 bytes encoded in base64
var zeroBytesB64 = base64.URLEncoding.EncodeToString(make([]byte, 32))
var inputToSigningTestVectors = []struct {
	name                 string
	input                inputToSigning
	percentEncodedOutput string
}{
	{
		name: "What the client signs",
		input: inputToSigning{
			prefix: PeerIDAuthScheme,
			params: map[string]string{"challenge-client": zeroBytesB64, "origin": "example.com"},
		},
		percentEncodedOutput: "libp2p-PeerID=challenge-client=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=%12origin=example.com",
	}, {
		name: "What the server signs",
		input: inputToSigning{
			prefix: PeerIDAuthScheme,
			params: map[string]string{"challenge-server": zeroBytesB64, "origin": "example.com", "client": zeroID.String()},
		},
		percentEncodedOutput: "libp2p-PeerID=challenge-server=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=%3Bclient=12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN%12origin=example.com",
	},
}

func TestSigningVectors(t *testing.T) {
	t.Run("Inputs to signing", func(t *testing.T) {
		for _, test := range inputToSigningTestVectors {
			t.Run(test.name, func(t *testing.T) {
				params := make([]string, 0, len(test.input.params))
				for k, v := range test.input.params {
					params = append(params, fmt.Sprintf("%s=%s", k, v))
				}
				out, err := genDataToSign(nil, test.input.prefix, params)
				require.NoError(t, err)
				require.Equal(t, test.percentEncodedOutput, url.PathEscape(string(out)))
			})
		}
	})
	t.Run("Client sig", func(t *testing.T) {
		client := ClientPeerIDAuth{PrivKey: zeroKey}
		challengeClient := make([]byte, challengeLen)
		origin := "example.com"
		sig, err := client.sign(challengeClient, origin)
		require.NoError(t, err)
		require.Equal(t, expectedClientSig, hex.EncodeToString(sig))
	})

	t.Run("Server sig", func(t *testing.T) {
		server := PeerIDAuth{PrivKey: zeroKey}
		challengeServer := make([]byte, challengeLen)
		origin := "example.com"
		sig, err := server.signChallengeServer(challengeServer, zeroID, origin)
		require.NoError(t, err)
		require.Equal(t, expectedServerSig, hex.EncodeToString(sig))
	})
}
