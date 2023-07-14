package orchestrator

import (
	"GoMapEnum/src/utils"
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Bruteforce will call the functions according the orchestrator options to bruteforce.
// Firstly, PreActionBruteforce
// Then, CustomOptionsForCheckIfValid mostly to change the log level for enumeration and avoid printing success if the user a checked before the bruteforce
// Afterthat, AuthenticationFunc to authenticate with the username and password
// Finally, PostActionBruteforce
func (orchestrator *Orchestrator) Bruteforce(optionsModules Options) string {
	var usernameList, passwordList []string
	optionsInterface := reflect.ValueOf(optionsModules).Interface()
	options := optionsModules.GetBaseOptions()
	var wg sync.WaitGroup
	var validUsers []string
	var throttledUsers []string
	var errorUsers []string
	var proxies []*url.URL
	var queue []string
	mux := &sync.Mutex{}
	proxyindex := 0
	throttledCount := 0
	//throtinroundCount := 0
	reqinround := 0
	roundsCount := 1
	errorCount := 0
	totalCount := 0
	stopflag := false
	showstat := true

	if orchestrator.PreActionBruteforce != nil {
		// If the PreActionUserEnum failed, just returned the list that is empty at this step
		if !orchestrator.PreActionBruteforce(&optionsInterface) {
			return strings.Join(validUsers, "\n")
		}
	}

	//catch ctrl+c and put in logfile unckecked user_pass - so U can use it in future brute
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if options.LogFile != "" {
			options.Log.Info(fmt.Sprintf("Catch CTRL+C.."))
			if options.LogFile != "" {
				options.Log.Info(fmt.Sprintf("Writing queue to logfile..."))
				for _, elem := range queue {
					options.Log.Info(fmt.Sprintf("Unchecked username_pass: %v", elem))
				}
			}
		}
		options.Log.Info(fmt.Sprintf("Exiting.."))
		os.Exit(1)
	}()

	//show Statistics every 60 sec
	go func() {
		uptimeTicker := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-uptimeTicker.C:
				if len(queue) > 0 && showstat {
					username := queue[0]
					queueLen := len(queue)
					if len(proxies) > 0 {
						options.Log.Info(fmt.Sprintf("Current statictics: Tried request in current round: %v, throttled requests: %v, Error requests: %v, Queue length %v, Current user_pass: %v, Current proxy: %s", reqinround, throttledCount, errorCount, queueLen, username, proxies[proxyindex]))
					} else {
						options.Log.Info(fmt.Sprintf("Current statictics: Tried request in current round: %v, throttled requests: %v, Error requests: %v, Queue length %v, Current user_pass: %v, Current proxy: NoProxy", reqinround, throttledCount, errorCount, queueLen, username))
					}
				}
			}
		}
	}()

	//read proxies from proxyfile
	if options.ProxyFile != "" {
		f, err := os.Open(options.ProxyFile)
		if err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				proxyurl, err := url.Parse(line)
				if err == nil {
					if proxyurl.Hostname() != "" && proxyurl.Port() != "" {
						proxies = append(proxies, proxyurl)
					}
				}
			}
		}
		if len(proxies) > 0 {
			proxyindex = 0
			options.ProxyHTTP = http.ProxyURL(proxies[proxyindex])
		}
	}

	if options.CheckIfValid {
		options.Log.Debug("Validating the users")
		if orchestrator.CustomOptionsForCheckIfValid != nil {
			optionsEnum := optionsInterface
			if orchestrator.CustomOptionsForCheckIfValid != nil {
				// Execute the function CustomOptionsForCheckIfValid mainly to change the log level and print only errors
				optionsEnum = orchestrator.CustomOptionsForCheckIfValid(&optionsInterface)
			}
			// If wee check if the users are valid before, we retrieve the usernameList from the Userenum function
			usernameList = strings.Split(orchestrator.UserEnum(optionsEnum.(Options)), "\n")
		} else {
			// Switch the mode to enumeration by default
			previousMode := optionsInterface.(Options).GetBaseOptions().Log.Mode
			optionsInterface.(Options).GetBaseOptions().Log.Mode = "Enumeration"
			usernameList = strings.Split(orchestrator.UserEnum(optionsModules), "\n")
			optionsInterface.(Options).GetBaseOptions().Log.Mode = previousMode
		}
	} else {
		options.Users = utils.GetStringOrFile(options.Users)
		usernameList = strings.Split(options.Users, "\n")
	}
	options.Passwords = utils.GetStringOrFile(options.Passwords)
	passwordList = strings.Split(options.Passwords, "\n")

	//making queue
	//check if no passwords file -> usersfile must be username:password
	if options.Passwords == "" {
		//let suppose that usernamelist contains combo list (user:pass)
		options.Log.Info(fmt.Sprintf("No passwords file provided. Suppose that users file contains username:password"))
		for _, username := range usernameList {
			username = strings.ToValidUTF8(username, "")
			username = strings.Trim(username, "\r")
			username = strings.Trim(username, "\n")
			if len(strings.Split(username, ":")) > 1 {
				queue = append(queue, username)
			}
		}
	} else {
		if options.StraightBrute {
			// Create direct list for user:password
			// user1:pass1, user1:pass2, user1,pass3...
			options.Log.Info(fmt.Sprintf("Using STRAIGHT bruteforce user1:password1, user1:password2, user1:password3, etc"))
			for _, username := range usernameList {

				username = strings.ToValidUTF8(username, "")
				username = strings.Trim(username, "\r")
				username = strings.Trim(username, "\n")
				if username == "" {
					continue
				}

				for _, pass := range passwordList {
					pass = strings.ToValidUTF8(pass, "")
					pass = strings.Trim(pass, "\r")
					pass = strings.Trim(pass, "\n")
					queue = append(queue, username+":"+pass)
				}
			}
		} else {
			// Create spray list for user:password
			// user1:pass1, user2:pass1, user3,pass1...
			options.Log.Info(fmt.Sprintf("Using SPRAY bruteforce user1:password1, user2:password1, user3:password1, etc"))
			for _, pass := range passwordList {

				pass = strings.ToValidUTF8(pass, "")
				pass = strings.Trim(pass, "\r")
				pass = strings.Trim(pass, "\n")

				for _, username := range usernameList {
					username = strings.ToValidUTF8(username, "")
					username = strings.Trim(username, "\r")
					username = strings.Trim(username, "\n")
					if username == "" {
						continue
					}
					queue = append(queue, username+":"+pass)
				}
			}
		}
	}

	//watcher fuction
	go func() {
		queuelength := len(queue)
		for {
			//check for throttled users and add them to the end of queue
			for len(throttledUsers) > 0 && options.ThrotAdd {
				mux.Lock()
				tuserpass := throttledUsers[0]
				throttledUsers[0] = ""
				throttledUsers = throttledUsers[1:]
				queue = append(queue, tuserpass)
				mux.Unlock()
			}

			//check for errors users and add them to the end of queue
			for len(errorUsers) > 0 && options.ErrorAdd {
				mux.Lock()
				euserpass := errorUsers[0]
				errorUsers[0] = ""
				errorUsers = errorUsers[1:]
				queue = append(queue, euserpass)

				mux.Unlock()
			}

			//check if rounds limit reached
			if options.RoundLimit > 0 && roundsCount > options.RoundLimit {
				//Doing roundAction
				options.Log.Info(fmt.Sprintf("Reached rounds limit. Rouds: %v. Total requests: %v.  Doind action: %s", roundsCount, totalCount, options.RoundAction))
				if strings.Contains(options.RoundAction, "sleep:") {
					//Doing sleep
					if len(strings.Split(options.RoundAction, ":")) > 1 {
						sleeptime, _ := strconv.Atoi(strings.Split(options.RoundAction, ":")[1])
						if sleeptime > 0 {
							//time.Sleep(time.Second * time.Duration(sleeptime))
							//need to tell all threads about sleeping
							stopflag = true
							showstat = false
							time.Sleep(time.Second * time.Duration(sleeptime))
							stopflag = false
							showstat = true
						}
					}
				}
				mux.Lock()
				throttledCount = 0
				reqinround = 0
				errorCount = 0
				roundsCount = 1
				mux.Unlock()
			}

			//check the throttlings and do actions if needed
			persent := 0
			if reqinround > 0 {
				persent = int((throttledCount * 100) / reqinround)
			}
			//if options.ThrotLimit > 0 && throttledCount >= options.ThrotLimit {
			if options.ThrotLimit > 0 && reqinround > (options.Thread*3) && persent > options.ThrotLimit {

				//Doing throttleAction
				options.Log.Info(fmt.Sprintf("Reached throttling limit. Throttled requests: %v. Requests in current round: %v.  Doind action: %s", throttledCount, reqinround, options.ThrotAction))
				if strings.Contains(options.ThrotAction, "sleep:") {
					//Doing sleep
					if len(strings.Split(options.ThrotAction, ":")) > 1 {
						sleeptime, _ := strconv.Atoi(strings.Split(options.ThrotAction, ":")[1])
						if sleeptime > 0 {
							//time.Sleep(time.Second * time.Duration(sleeptime))
							//need to tell all threads about sleeping
							stopflag = true
							showstat = false
							time.Sleep(time.Second * time.Duration(sleeptime))
							stopflag = false
							showstat = true
						}
					}
				}
				if strings.Contains(options.ThrotAction, "script:") {
					//TODO execute user script
				}
				if strings.Contains(options.ThrotAction, "nextproxy") {
					if len(proxies) > 0 {
						proxyindex++
						if proxyindex >= len(proxies) {
							proxyindex = 0
						}
						options.Log.Info(fmt.Sprintf("Change proxy to: %v. ", proxies[proxyindex]))
						options.ProxyHTTP = http.ProxyURL(proxies[proxyindex])
					}
				}
				mux.Lock()
				throttledCount = 0
				reqinround = 0
				errorCount = 0
				roundsCount++
				mux.Unlock()
			}

			//check the errors and do actions if needed
			persent = 0
			if reqinround > 0 {
				persent = int(errorCount / reqinround * 100)
			}
			if options.ErrorLimit > 0 && reqinround > 10 && persent > options.ErrorLimit {
				//Doing throttleAction
				options.Log.Info(fmt.Sprintf("Reached errors limit. Error in requests: %v. Requests in current round: %v.  Doind action: %s", errorCount, reqinround, options.ErrorAction))
				if strings.Contains(options.ErrorAction, "sleep:") {
					//Doing sleep
					if len(strings.Split(options.ThrotAction, ":")) > 1 {
						sleeptime, _ := strconv.Atoi(strings.Split(options.ThrotAction, ":")[1])
						if sleeptime > 0 {
							time.Sleep(time.Second * time.Duration(sleeptime))
						}
					}
				}
				if strings.Contains(options.ErrorAction, "script:") {
					//TODO execute user script
				}
				if strings.Contains(options.ErrorAction, "nextproxy") {
					if len(proxies) > 0 {
						proxyindex++
						if proxyindex >= len(proxies) {
							proxyindex = 0
						}
						options.Log.Info(fmt.Sprintf("Change proxy to: %v. ", proxies[proxyindex]))
						options.ProxyHTTP = http.ProxyURL(proxies[proxyindex])
					}
				}
				mux.Lock()
				errorCount = 0
				throttledCount = 0
				reqinround = 0
				roundsCount++
				mux.Unlock()
			}
			//quit when no more users to bruteforce
			if len(queue) == 0 && len(throttledUsers) == 0 && len(errorUsers) == 0 {
				break
			}

			//quit if totalcount more than 10 * original queue length
			if totalCount > (queuelength * 10) {
				options.Log.Info(fmt.Sprintf("Exiting because totalcount %v is more than 10 x queue original length ", totalCount))
				break
			}
			time.Sleep(time.Millisecond * 300)
		}
	}()

	// Start the workers
	for i := 0; i < options.Thread; i++ {
		wg.Add(1)
		go func(threadindex int) {
			defer wg.Done()

			for len(queue) > 0 {
				//found := false

				//check for stopflag and wait until it false
				for {
					if stopflag {
						time.Sleep(time.Millisecond * 500)
					} else {
						break
					}
				}

				mux.Lock()
				username := strings.Split(queue[0], ":")[0]
				password := ""
				if len(strings.Split(queue[0], ":")) > 1 {
					password = strings.Split(queue[0], ":")[1]
				} else {
					password = ""
				}
				queue[0] = ""
				queue = queue[1:]
				mux.Unlock()

				//check if username is in throttledUsers slice
				//and skip it if an options.StopOnLockout is set
				if utils.PartStringInSlice(throttledUsers, username) && options.StopOnLockout {
					options.Log.Verbose("Account " + username + " is locked. Skipping it.")
					continue
				}

				options.Log.Verbose("Testing " + username + " : " + password)
				if options.Sleep != 0 {
					// Sleep to avoid detection and bypass rate-limiting
					options.Log.Debug("Sleeping " + strconv.Itoa(options.Sleep) + " seconds")
					time.Sleep(time.Duration(options.Sleep) * time.Second)
				}
				mux.Lock()
				totalCount++
				reqinround++
				mux.Unlock()
				resbool, rescode := orchestrator.AuthenticationFunc(&optionsInterface, username, password)
				if resbool {
					mux.Lock()
					validUsers = append(validUsers, username+" / "+password)
					mux.Unlock()
					//found = true
					options.Log.Success(username + " / " + password)
					//break // No need to continue if password is valid
				} else {
					if rescode == 0 {
						options.Log.Fail(username + " / " + password)
					}
					if rescode == 1 {
						//locked account
						options.Log.Fail(username + " is locked / throttled. We'll recheck it later..")
						mux.Lock()
						throttledUsers = append(throttledUsers, username+":"+password)
						throttledCount++
						//throtinroundCount++
						mux.Unlock()
					}
					if rescode == 2 {
						//error in bruteforce attempt
						options.Log.Fail("Some errror when trying " + username + " / " + password)
						mux.Lock()
						errorUsers = append(errorUsers, username+":"+password)
						errorCount++
						mux.Unlock()
					}
				}

				/*
					if options.NoBruteforce {
						// If no bruteforce we log with the first item in username list and password list, then the second and so one...
						index := utils.IndexInSlice(usernameList, username)
						resultbool, _ := orchestrator.AuthenticationFunc(&optionsInterface, username, passwordList[index])
						if resultbool {
							mux.Lock()
							validUsers = append(validUsers, username+" / "+passwordList[index])
							mux.Unlock()
							found = true
							options.Log.Success(username + " / " + passwordList[index])
						} else {
							options.Log.Fail(username + " / " + passwordList[index])
						}
					} else {
						// If bruteforce we test for each password in the list
						for _, password := range passwordList {
							resultbool, _ := orchestrator.AuthenticationFunc(&optionsInterface, username, password)
							if resultbool {
								mux.Lock()
								validUsers = append(validUsers, username+" / "+password)
								mux.Unlock()
								found = true
								options.Log.Success(username + " / " + password)
								break // No need to continue if password is valid
							} else {
								options.Log.Fail(username + " / " + password)
							}
						}
					}


					if !found {
						options.Log.Verbose("No password matched for " + username)
					}

				*/
			}

		}(i)
	}
	// Trim emails and send them to the pool of workers

	//close(queue)
	// Wait all workers
	wg.Wait()

	// Doing the post action
	if orchestrator.PostActionBruteforce != nil {
		if !orchestrator.PostActionBruteforce(&optionsInterface) {
			return strings.Join(validUsers, "\n")
		}
	}
	return strings.Join(validUsers, "\n")
}
