package managers

import (
	"encoding/base64"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

func GenerateQRCodeBase64(content string) (string, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
