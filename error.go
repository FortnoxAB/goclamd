package goclamd

import "fmt"

// VirusFoundError is a custom error where we can get the virus name from Virus() method
type VirusFoundError struct {
	virus string
	res   string
}

func NewVirusFoundError(res []byte, virus []byte) error {
	return &VirusFoundError{
		res:   string(res),
		virus: string(virus),
	}
}

func (vfe *VirusFoundError) Error() string {
	return fmt.Sprintf("%s: %s", vfe.Resolution(), vfe.Virus())
}
func (vfe *VirusFoundError) Virus() string {
	return vfe.virus
}
func (vfe *VirusFoundError) Resolution() string {
	return vfe.res
}

func IsVirusErr(err error) *VirusFoundError {
	if vfe, ok := err.(*VirusFoundError); ok {
		return vfe
	}
	return nil
}
