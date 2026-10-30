package proxy

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net"
	"strings"
)

func constantEqual(a,b string) bool {
	if len(a)!=len(b) {return false}
	return subtle.ConstantTimeCompare([]byte(a),[]byte(b))==1
}
func (s *Server) httpAuthorized(value string) bool {
	if s.config==nil || s.config.Username=="" {return true}
	fields:=strings.SplitN(value," ",2)
	if len(fields)!=2 || !strings.EqualFold(fields[0],"Basic") {return false}
	data,err:=base64.StdEncoding.DecodeString(fields[1])
	if err!=nil {return false}
	parts:=strings.SplitN(string(data),":",2)
	return len(parts)==2 && constantEqual(parts[0],s.config.Username) && constantEqual(parts[1],s.config.Password)
}
func (s *Server) socksAuthorized(conn net.Conn, reader *bufio.Reader) bool {
	h:=make([]byte,2)
	if _,err:=io.ReadFull(reader,h);err!=nil || h[0]!=1 || h[1]==0 {return false}
	user:=make([]byte,int(h[1]))
	if _,err:=io.ReadFull(reader,user);err!=nil {return false}
	size:=make([]byte,1)
	if _,err:=io.ReadFull(reader,size);err!=nil || size[0]==0 {return false}
	pass:=make([]byte,int(size[0]))
	if _,err:=io.ReadFull(reader,pass);err!=nil {return false}
	valid:=constantEqual(string(user),s.config.Username)&&constantEqual(string(pass),s.config.Password)
	result:=byte(1)
	if valid {result=0}
	if _,err:=conn.Write([]byte{1,result});err!=nil {return false}
	return valid
}
