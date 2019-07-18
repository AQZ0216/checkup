package checkup

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	gomail "gopkg.in/gomail.v2"
)

// Gmail consist of all the sub components required to use gomail API
type Gmail struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	MailList string `json:"list"`
}

// Notify implements notifier interface
func (s Gmail) Notify(results []Result) error {
	for _, result := range results {
		if !result.Healthy {
			s.Send(result)
		}
	}
	return nil
}

func (s Gmail) NotifyAll(results []Result) error {
	var result Result
	var buf bytes.Buffer
	buf.WriteString("<html lang=\"en\" encoding=\"utf-8\"><head><title>cybavo daily report</title></head><TABLE width=\"70%\" frame=\"none\"  border=\"1\"><body><TR><TH>Title</TH> <TH>Endpoint</TH> <TH>status</TH></TR>")

	for _, resultitem := range results {
		tmp := fmt.Sprintf("<TR><TH>%s</TH><TH>%s </TH> <TH>%s</TH></TR>\n", resultitem.Title, resultitem.Endpoint, string(resultitem.Status()))
		buf.WriteString(tmp)
	}

	buf.WriteString("</TABLE></body></html>")
	result.Title = "Health Check status report."
	result.Message = buf.String()
	result.Healthy = true
	s.Send(result)
	return nil
}

// Send request via gomail API to create incident
func (s Gmail) Send(result Result) error {
	d := gomail.NewDialer("smtp.gmail.com", 465, s.Username, s.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	m := gomail.NewMessage()
	m.SetHeader("From", s.Username)
	m.SetHeader("To", strings.Split(s.MailList, ",")...)
	m.SetHeader("Subject", fmt.Sprintf("%s: %s is %s", result.Title, result.Endpoint, string(result.Status())))

	m.SetBody("text/html", result.Message)

	err := d.DialAndSend(m)
	if err != nil {
		log.Printf("ERROR: %s", err)
	}
	log.Printf("Create request for %s", result.Endpoint)

	return nil
}
