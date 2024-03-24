package gocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

// https://tools.ietf.org/html/rfc6960#section-4.2.1
// https://tools.ietf.org/html/rfc6960#appendix-B.2

var OidOcspBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

type OcspResponse struct {
	// ResponseStatus ENUMERATED {
	//    successful            (0), -- Response has valid confirmations
	//    malformedRequest      (1), -- Illegal confirmation request
	//    internalError         (2), -- Internal error in issuer
	//    tryLater              (3), -- Try again later
	//                               -- (4) is not used
	//    sigRequired           (5), -- Must sign the request
	//    unauthorized          (6), -- Request unauthorized
	// }
	ResponseStatus asn1.Enumerated
	ResponseBytes  responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type BasicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Version int `asn1:"default:0,explicit,tag:0,optional"`
	// ResponderID has to be either Name or KeyHash (SHA-1 hash of responder's public key, excluding the tag and length fields)
	ResponderID        asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []singleResponse
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponse struct {
	CertID certID
	// CertStatus CHOICE {
	//    good                [0]     IMPLICIT NULL,
	//    revoked             [1]     IMPLICIT RevokedInfo,
	//    unknown             [2]     IMPLICIT UnknownInfo,
	// }
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          RevokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type RevokedInfo struct {
	RevocationTime   time.Time       `asn1:"generalized"`
	RevocationReason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

func (ri *RevokedInfo) IsEmpty() bool {
	if ri.RevocationTime.IsZero() || ri.RevocationTime.Equal(time.Time{}) {
		return true
	}
	return false
}

func UnmarshalResponse(response []byte) (*OcspResponse, error) {
	var ocspResponse OcspResponse
	rest, err := asn1.Unmarshal(response, &ocspResponse)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data in OCSP response")
	}

	return &ocspResponse, nil
}

func UnmarshalResponseToBasic(response []byte) (*BasicResponse, error) {
	var ocspResponse OcspResponse
	rest, err := asn1.Unmarshal(response, &ocspResponse)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data in OCSP response")
	}
	basicResponse, err := UnmarshalBasicResponse(ocspResponse.ResponseBytes.Response)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data in OCSP basic response")
	}

	return basicResponse, nil
}

func MarshalResponse(response *OcspResponse) ([]byte, error) {
	r, err := asn1.Marshal(*response)
	if err != nil {
		return nil, err
	}
	return r, err
}

func MarshalResponseFromBasic(basicResponse *BasicResponse) ([]byte, error) {
	for _, sr := range basicResponse.TBSResponseData.Responses {
		if sr.Good == false && sr.Revoked.IsEmpty() {
			sr.Unknown = true
		}
	}
	b, err := MarshalBasicResponse(basicResponse)
	if err != nil {
		return nil, err
	}
	response := OcspResponse{
		ResponseStatus: asn1.Enumerated(0),
		ResponseBytes: responseBytes{
			ResponseType: OidOcspBasicResponse,
			Response:     b,
		},
	}
	r, err := asn1.Marshal(response)
	if err != nil {
		return nil, err
	}
	return r, err
}

func UnmarshalBasicResponse(basicResponse []byte) (*BasicResponse, error) {
	var basic BasicResponse
	rest, err := asn1.Unmarshal(basicResponse, &basic)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data in OCSP basic response")
	}
	return &basic, nil
}

func MarshalBasicResponse(basicResponse *BasicResponse) ([]byte, error) {
	for i, sr := range basicResponse.TBSResponseData.Responses {
		if sr.Good == true && sr.Unknown == true {
			// Copy good but unknown
			var s singleResponse
			s.CertID = sr.CertID
			s.ThisUpdate = sr.ThisUpdate
			s.NextUpdate = sr.NextUpdate
			s.SingleExtensions = sr.SingleExtensions
			s.Good = true
			basicResponse.TBSResponseData.Responses[i] = s
		} else if !sr.Revoked.IsEmpty() && sr.Unknown == true {
			// Copy revoked but unknown
			var s singleResponse
			s.CertID = sr.CertID
			s.ThisUpdate = sr.ThisUpdate
			s.NextUpdate = sr.NextUpdate
			s.SingleExtensions = sr.SingleExtensions
			s.Revoked = sr.Revoked
			basicResponse.TBSResponseData.Responses[i] = s
		} else if sr.Good == false && sr.Revoked.IsEmpty() {
			// Set unknown if there was no status.
			var s singleResponse
			s.CertID = sr.CertID
			s.ThisUpdate = sr.ThisUpdate
			s.NextUpdate = sr.NextUpdate
			s.SingleExtensions = sr.SingleExtensions
			s.Unknown = true
			basicResponse.TBSResponseData.Responses[i] = s
		}

	}
	b, err := asn1.Marshal(*basicResponse)
	return b, err
}

func (basicResponse *BasicResponse) SetNonce(index int, nonce []byte) {
	done := false
	extList := basicResponse.TBSResponseData.Responses[index].SingleExtensions
	if len(extList) == 0 {
		// There is no Nonce extension, add it.
		nonceExt := pkix.Extension{
			Id:       OidOcspNonce,
			Critical: false,
			Value:    nonce,
		}
		extList = append(extList, nonceExt)
		done = true
	} else {
		for _, extension := range extList {
			if extension.Id.Equal(OidOcspNonce) {
				extension.Value = nonce
				done = true
			}
		}
		if !done {
			// There is no Nonce extension, add it.
			nonceExt := pkix.Extension{
				Id:       OidOcspNonce,
				Critical: false,
				Value:    nonce,
			}
			extList = append(extList, nonceExt)
		}
	}
	basicResponse.TBSResponseData.Responses[index].SingleExtensions = extList
}

func (basicResponse *BasicResponse) GetNonce(index int) []byte {
	extList := basicResponse.TBSResponseData.Responses[index].SingleExtensions
	if len(extList) == 0 {
		// There is no Nonce extension.
		return nil
	} else {
		for _, extension := range extList {
			if extension.Id.Equal(OidOcspNonce) {
				return extension.Value
			}
		}
	}
	// There is no Nonce extension.
	return nil
}

func (basicResponse *BasicResponse) ClearStatus(index int) {
	basicResponse.TBSResponseData.Responses[index].Good = false
	basicResponse.TBSResponseData.Responses[index].Unknown = false
	basicResponse.TBSResponseData.Responses[index].Revoked = RevokedInfo{}
}
