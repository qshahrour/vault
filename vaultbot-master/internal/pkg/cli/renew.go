package cli

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// ExecuteRenewHook performs a specified os command
func ExecuteRenewHook(command string) {
	args := strings.Fields(command)
	bin := args[0]
	args = args[1:]

	cmd := exec.Command(bin, args...)
	log.Printf("Running renew-hook: %s", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error executing renew-hook: %s, output: %s", err, output)
	}
	log.Printf("Executed renew-hook successfully!")
}

// UserConfirmation prompts the user with a message and returns true or false based on the users response
func UserConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)

	for i := 0; i < 4; i++ {
		fmt.Printf("%s [y/n]: ", prompt)

		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		input = strings.ToLower(strings.TrimSpace(input))

		if input == "y" {
			return true
		} else if input == "n" {
			return false
		}
	}

	return false
}
