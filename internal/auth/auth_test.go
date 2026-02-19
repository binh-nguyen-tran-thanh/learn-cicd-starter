package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError bool
		errorType     error
	}{
		{
			name:          "valid api key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			expectedKey:   "test-key-123",
			expectedError: false,
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: true,
			errorType:     ErrNoAuthHeaderIncluded,
		},
		{
			name:          "empty authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: true,
			errorType:     ErrNoAuthHeaderIncluded,
		},
		{
			name:          "malformed header - wrong scheme",
			headers:       http.Header{"Authorization": []string{"Bearer test-key"}},
			expectedKey:   "",
			expectedError: true,
		},
		{
			name:          "malformed header - no space",
			headers:       http.Header{"Authorization": []string{"ApikeyTest"}},
			expectedKey:   "",
			expectedError: true,
		},
		{
			name:          "malformed header - only scheme",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)
			if (err != nil) != tc.expectedError {
				t.Errorf("expected error: %v, got: %v", tc.expectedError, err != nil)
			}
			if key != tc.expectedKey {
				t.Errorf("expected key: %s, got: %s", tc.expectedKey, key)
			}
		})
	}
}
