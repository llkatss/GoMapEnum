package ldap

import (
	"GoMapEnum/src/logger"
	"GoMapEnum/src/modules/ldap"
	"GoMapEnum/src/orchestrator"

	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
)

// bruteCmd represents the owa command
var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Authenticate on LDAP",
	Long:  ``,
	Example: `go run main.go owa brute -u users -p pass -t mail.contoso.com -s 10 -o validUsers
go run main.go owa brute -u john.doe@contoso.com -p Automn2021! -t mail.contoso.com -v`,

	Run: func(cmdCli *cobra.Command, args []string) {
		log := logger.New("Bruteforce", "LDAP", ldapOptions.Target)
		log.SetLevel(level)
		log.Info("Starting the module LDAP")
		ldapOptions.Log = log

		// If we bruteforce with hash, password will contains the hashs as we use the orchestrator and we want to keep the same format than CME
		if ldapOptions.Hash != "" {
			ldapOptions.Passwords = ldapOptions.Hash
			ldapOptions.IsHash = true
		}

		orchestratorOptions := orchestrator.Orchestrator{}
		orchestratorOptions.AuthenticationFunc = ldap.Authenticate
		orchestratorOptions.PreActionBruteforce = ldap.RetrieveTargetInfo
		outputCmd = orchestratorOptions.Bruteforce(&ldapOptions)

	},
}

func init() {

	bruteCmd.Flags().BoolVarP(&ldapOptions.NoBruteforce, "no-bruteforce", "n", false, "No spray when using file for username and password (user1 => password1, user2 => password2)")
	bruteCmd.Flags().IntVar(&ldapOptions.Thread, "thread", 2, "Number of threads")
	bruteCmd.Flags().IntVar(&ldapOptions.Timeout, "timeout", int(ldaplib.DefaultTimeout.Seconds()), "Timeout for the SMB connection in seconds")
	bruteCmd.Flags().IntVarP(&ldapOptions.Sleep, "sleep", "s", 0, "Sleep in seconds before sending an authentication request")

}
