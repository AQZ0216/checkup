package checkup

import (
	"fmt"

	telegram "github.com/go-telegram-bot-api/telegram-bot-api"
)

// Telegram consist of all the sub components required to use Telegram API
type Telegram struct {
	Token   string `json:"token"`
	GroupID int64  `json:"groupId"`
}

// Notify implements notifier interface
func (t Telegram) Notify(results []Result) error {
	bot, err := telegram.NewBotAPI(t.Token)
	if err != nil {
		return err
	}

	for _, result := range results {
		if !result.Healthy {
			t.Send(result, bot)
		}
	}
	return nil
}

// Notify implements notifier interface
func (t Telegram) NotifyAll(results []Result) error {
	bot, err := telegram.NewBotAPI(t.Token)
	if err != nil {
		return err
	}

	for _, result := range results {
		t.Send(result, bot)
	}
	return nil
}

// Send request via Telegram API
func (t Telegram) Send(result Result, bot *telegram.BotAPI) error {
	var msg telegram.MessageConfig

	if result.Down {
		msg = telegram.NewMessage(t.GroupID, fmt.Sprintf("%s: %s is %s, error=%s", result.Title, result.Endpoint, string(result.Status()), result.Message))
	} else {
		msg = telegram.NewMessage(t.GroupID, fmt.Sprintf("%s: %s is %s", result.Title, result.Endpoint, string(result.Status())))
	}

	bot.Send(msg)
	return nil
}
