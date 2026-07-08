package forwarder

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// dialHTTPConnect connects to dest via an HTTP proxy using the CONNECT method.
func dialHTTPConnect(proxyURL *url.URL, dest string) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = proxyAddr + ":8080"
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy %s: %w", proxyAddr, err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: dest},
		Host:   dest,
		Header: make(http.Header),
	}

	// Set proxy authentication if present
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		req.SetBasicAuth(username, password)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT returned %d %s", resp.StatusCode, resp.Status)
	}

	return conn, nil
}
