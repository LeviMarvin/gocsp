package gocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

var OidOcspNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// https://tools.ietf.org/html/rfc6960#section-4.1.1
// https://tools.ietf.org/html/rfc6960#appendix-B.2

type OcspRequest struct {
	TBSRequest tbsRequest
	Signature  signature `asn1:"explicit,tag:0,optional"`
}

type signature struct {
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              [][]asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tbsRequest struct {
	Version       int              `asn1:"default:0,explicit,tag:0,optional"`
	RequestorName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	RequestList   []request
	ExtensionList []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type request struct {
	ReqCert                 certID
	SingleRequestExtensions []pkix.Extension `asn1:"explicit,tag:0,optional"`
}

// UnmarshalRequest unmarshals an OCSP request from a byte slice into an OcspRequest struct.
//
// It takes a byte slice as input parameter and returns a pointer to an OcspRequest struct and an error.
// The function uses the asn1.Unmarshal function to decode the byte slice into the OcspRequest struct.
// If there is an error during unmarshaling, the function returns nil and the error.
// If there is trailing data in the byte slice, the function returns nil and an error indicating trailing data.
// Otherwise, it returns a pointer to the OcspRequest struct and nil error.
func UnmarshalRequest(request []byte) (*OcspRequest, error) {
	var req OcspRequest
	rest, err := asn1.Unmarshal(request, &req)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data in OCSP request")
	}
	return &req, nil
}

// MarshalRequest marshals the given ocspRequest into its ASN.1 DER encoding.
//
// ocspRequest: The OCSP request to be marshaled.
// []byte: The marshaled OCSP request in ASN.1 DER encoding.
// error: An error if the marshaling process fails.
func MarshalRequest(ocspRequest *OcspRequest) ([]byte, error) {
	b, err := asn1.Marshal(*ocspRequest)
	return b, err
}

// Nonce returns the nonce from the OcspRequest struct.
//
// No parameters.
// Returns a byte slice with the nonce value from request, or nil for no nonce.
func (r *OcspRequest) Nonce() []byte {
	for _, extension := range r.TBSRequest.ExtensionList {
		if extension.Id.Equal(OidOcspNonce) {
			return extension.Value
		}
	}
	return nil
}
