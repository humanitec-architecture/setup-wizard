package message

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aripalo/go-delightful"
	"github.com/enescakir/emoji"
)

var message = delightful.New("humctl-wizard")

func SetSilentMode(flag bool) {
	message.SetSilentMode(flag)
}

func SetVerboseMode(flag bool) {
	message.SetVerboseMode(flag)
}

func SetEmojiMode(flag bool) {
	message.SetEmojiMode(flag)
}

func SetColorMode(flag bool) {
	message.SetColorMode(flag)
}

func Select(message string, options []string) (string, error) {
	var answer string
	prompt := survey.Select{
		Message: message,
		Options: options,
	}

	err := survey.AskOne(&prompt, &answer)
	if err != nil {
		return "", fmt.Errorf("failed to ask question: %w", err)
	}

	return answer, nil
}

func MultipleSelect(message string, options []string) ([]string, error) {
	var answers []string
	prompt := survey.MultiSelect{
		Message: message,
		Options: options,
	}

	err := survey.AskOne(&prompt, &answers)
	if err != nil {
		return nil, fmt.Errorf("failed to ask question: %w", err)
	}

	return answers, nil
}

func BoolSelect(message string) (bool, error) {
	var answer bool
	prompt := &survey.Confirm{
		Message: message,
	}

	err := survey.AskOne(prompt, &answer)
	if err != nil {
		return false, fmt.Errorf("failed to ask question: %w", err)
	}

	return answer, nil
}

func Prompt(message string, defaultValue string) (string, error) {
	var answer string
	prompt := &survey.Input{
		Message: message,
		Default: defaultValue,
	}

	err := survey.AskOne(prompt, &answer)
	if err != nil {
		return "", fmt.Errorf("failed to ask question: %w", err)
	}

	return answer, nil
}

func Debug(format string, args ...any) {
	message.Debugln(emoji.HammerAndWrench, fmt.Sprintf(format, args...))
}

func Info(format string, args ...any) {
	message.Infoln(emoji.Information, fmt.Sprintf(format, args...))
}

func Success(format string, args ...any) {
	message.Infoln(emoji.CheckMarkButton, fmt.Sprintf(format, args...))
}

func Error(format string, args ...any) {
	message.Failureln(emoji.CrossMark, fmt.Sprintf(format, args...))
}