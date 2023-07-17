package o365

import (
	"GoMapEnum/src/logger"
	"GoMapEnum/src/modules/o365"
	"GoMapEnum/src/orchestrator"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

// enumCmd represents the azure command
var enumCmd = &cobra.Command{
	Use:   "userenum",
	Short: "User enumeration through autlogon API",
	Long: `The authentication process does not seem to work but the error code can still give information if the user's account exist or not
	Credits https://github.com/treebuilder/aad-sso-enum-brute-spray`,
	Example: `go run main.go o365 userenum -u john.doe@contoso.com
	go run main.go o365 userenum -u users -o validUsers`,
	Run: func(cmdCli *cobra.Command, args []string) {
		log := logger.New("Enumeration", "O365", "https://login.microsoftonline.com")
		log.SetLevel(level)
		log.Info("Starting the module O365")
		if o365Options.LogFile != "" {
			log.File = o365Options.LogFile
		}
		o365Options.Log = log

		orchestratorOptions := orchestrator.Orchestrator{}
		orchestratorOptions.PreActionUserEnum = o365.InitData
		orchestratorOptions.UserEnumFunc = o365.UserEnum
		validUsers = orchestratorOptions.UserEnum(&o365Options)
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if output != "" {

			if err := os.WriteFile(output, []byte(validUsers), 0666); err != nil {
				fmt.Println(err)
			}
		}
	},
}

func init() {

	enumCmd.Flags().StringVarP(&o365Options.Users, "user", "u", "", "User or file containing the emails")
	enumCmd.Flags().IntVar(&o365Options.Thread, "thread", 2, "Number of threads")
	enumCmd.Flags().IntVar(&o365Options.ReqMultiplier, "reqmultiplier", 200, "Request multiplier")
	enumCmd.Flags().StringVarP(&o365Options.Mode, "mode", "m", "office", "Choose a mode between office and oauth2 (office mode does not try to authenticate) ")
	enumCmd.Flags().Float32Var(&o365Options.ThrotLimit, "throtlim", 0, "Limit of throttling in requests")
	enumCmd.Flags().BoolVar(&o365Options.ThrotAdd, "throtadd", false, "Add throttled users to the queue")
	enumCmd.Flags().BoolVar(&o365Options.ErrorAdd, "erradd", false, "Add error users to the queue")
	enumCmd.Flags().Float32Var(&o365Options.ErrorLimit, "errorlim", 0, "Limit of errors in requests")
	enumCmd.Flags().StringVarP(&o365Options.LogFile, "logfile", "", "", "LogFile to write (additionally with console)")
	enumCmd.Flags().StringVarP(&o365Options.ProxyFile, "proxyfile", "", "", "File with proxies")
	enumCmd.Flags().StringVarP(&o365Options.ThrotAction, "throtaction", "", "", "do this after the limit of throttling more than throtlim. Ex for sleep 30 sec: sleep:30")
	enumCmd.Flags().StringVarP(&o365Options.ErrorAction, "erroraction", "", "", "do this after the limit of errors more than errorlim. Ex: nextproxy")

	err := enumCmd.MarkFlagRequired("user")
	if err != nil {
		log.Fatal(err)
	}
}
