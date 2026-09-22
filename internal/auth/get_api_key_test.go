package auth

import (
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := []struct {
		name    string
		auth    string
		wantKey string
		wantErr string
	}{
		{
			name:    "no header Auth",
			wantErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:    "wrong auth schema",
			auth:    "Bearer abc123",
			wantErr: "malformed authorization header",
		},
		{
			name:    "no key after ApiKey",
			auth:    "ApiKey",
			wantErr: "malformed authorization header",
		},
		{
			name:    "valid ApiKey",
			auth:    "ApiKey abc123",
			wantKey: "abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.auth != "" {
				headers.Set("Authorization", tt.auth)
			}
			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("key: got %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantErr == "" && err != nil {
				t.Fatalf("not expected error: %v", err)
			}

			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expecter error, got nil")
				}
				if err.Error() != tt.wantErr {
					t.Errorf("error: expected %q, got %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}
