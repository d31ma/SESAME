import (
	"errors"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

type ProtocolErrorUtils struct{}

func (ProtocolErrorUtils) Code(failure error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(failure, &protocolError)
	return protocolError.Code
}
