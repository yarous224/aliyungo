package oss

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var (
	publicKeys              sync.Map
	urlReg                  = regexp.MustCompile(`^http(|s)://gosspublic.alicdn.com/[0-9a-zA-Z]`)
	CertificateAddressError = errors.New("certificate address error")
	CertificateDataError    = errors.New("certificate data error")
)

//验证OSS向业务服务器发来的回调函数。
//该方法是并发安全的
//pubKeyUrl 回调请求头中[x-oss-pub-key-url]一项，以Base64编码
//reqUrl oss所发来请求的url，由path+query组成
//reqBody oss所发来请求的body
//authorization authorization为回调头中的签名
func AuthenticateCallBack(pubKeyUrl, reqUrl, reqBody, authorization string) error {
	//获取证书url
	keyURL, err := base64.URLEncoding.DecodeString(pubKeyUrl)
	if err != nil {
		return err
	}
	url := string(keyURL)
	//判断证书是否来自于阿里云
	if !urlReg.Match(keyURL) {
		return CertificateAddressError
	}
	//获取文件名
	urlRunes := []rune(url)
	filename := string(urlRunes[strings.LastIndex(url, "/") : len(urlRunes)-1])
	certificate, ok := publicKeys.Load(filename)
	if !ok {
		res, err := http.Get(url)
		if err != nil {
			return err
		}

		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(body)
		if block == nil {
			return CertificateDataError
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		certificate = pubKey
		publicKeys.Store(filename, certificate)
	}
	//证书准备完毕，开始验证
	//解析签名
	signature, err := base64.StdEncoding.DecodeString(authorization)
	if err != nil {
		return err
	}

	hashed := md5.Sum([]byte(reqUrl + "\n" + reqBody))
	return rsa.VerifyPKCS1v15(certificate.(*rsa.PublicKey), crypto.MD5, hashed[:], signature)
}
