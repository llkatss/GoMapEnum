package orchestrator

import (
	"GoMapEnum/src/utils"
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UserEnum will call the functions according the orchestrator options to enumerate valid users.
// Firstly, PreActionUserEnum
// Then for each user, the function CheckBeforeEnumFunc
// After that, UserEnumFunc
// Finally, PostActionUserEnum
func (orchestrator *Orchestrator) UserEnum(optionsModules Options) string {
	optionsInterface := reflect.ValueOf(optionsModules).Interface()
	options := optionsModules.GetBaseOptions()
	options.Users = utils.GetStringOrFile(options.Users)
	options.UsernameList = strings.Split(options.Users, "\n")
	mux := &sync.Mutex{}
	var wg sync.WaitGroup
	var validUsers []string
	var throttledUsers []string
	var errorUsers []string
	var proxies []*url.URL
	proxyindex := 0
	throttledCont := 0
	errorCount := 0
	totalCount := 0
	//queue := make(chan string)
	var queue []string
	if orchestrator.PreActionUserEnum != nil {
		// If the PreActionUserEnum failed, just returned the list that is empty at this step
		if !orchestrator.PreActionUserEnum(&optionsInterface) {
			return strings.Join(validUsers, "\n")
		}
	}

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

	//show Statistics every 60 sec
	go func() {
		uptimeTicker := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-uptimeTicker.C:
				if len(proxies) > 0 {
					options.Log.Info(fmt.Sprintf("Current statictics: Tried requests: %v, throttled requests: %v, Error requests: %v, Current proxy: %s", totalCount, throttledCont, errorCount, proxies[proxyindex]))
				} else {
					options.Log.Info(fmt.Sprintf("Current statictics: Tried requests: %v, throttled requests: %v, Error requests: %v, Current proxy: NoProxy", totalCount, throttledCont, errorCount))
				}
			}
		}

	}()

	//watcher fuction
	go func() {
		for {

			//check for throttled users and add them to the end of queue
			for len(throttledUsers) > 0 && options.ThrotAdd {
				mux.Lock()
				tusername := throttledUsers[0]
				throttledUsers[0] = ""
				throttledUsers = throttledUsers[1:]
				queue = append(queue, tusername)
				mux.Unlock()
			}

			//check for errors users and add them to the end of queue
			for len(errorUsers) > 0 && options.ErrorAdd {
				mux.Lock()
				eusername := errorUsers[0]
				errorUsers[0] = ""
				errorUsers = errorUsers[1:]
				queue = append(queue, eusername)
				mux.Unlock()
			}

			//check the throttlings and do actions if needed
			if options.ThrotLimit > 0 && throttledCont >= options.ThrotLimit {
				//Doing throttleAction
				options.Log.Info(fmt.Sprintf("Reached throttling limit. Throttled requests: %v. Total requests: %v.  Doind action: %s", throttledCont, totalCount, options.ThrotAction))
				if strings.Contains(options.ThrotAction, "sleep:") {
					//Doing sleep
					if len(strings.Split(options.ThrotAction, ":")) > 1 {
						sleeptime, _ := strconv.Atoi(strings.Split(options.ThrotAction, ":")[1])
						if sleeptime > 0 {
							time.Sleep(time.Second * time.Duration(sleeptime))
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
				throttledCont = 0
				errorCount = 0
				mux.Unlock()
			}

			//check the errors and do actions if needed
			if options.ErrorLimit > 0 && errorCount >= options.ErrorLimit {
				//Doing throttleAction
				options.Log.Info(fmt.Sprintf("Reached errors limit. Error in requests: %v. Total requests: %v.  Doind action: %s", errorCount, totalCount, options.ErrorAction))
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
				throttledCont = 0
				mux.Unlock()
			}

			if len(queue) == 0 && len(throttledUsers) == 0 && len(errorUsers) == 0 {
				break
			}
			time.Sleep(time.Millisecond * 300)
		}
	}()

	// Trim usernames and send them to the queue
	for _, username := range options.UsernameList {

		username = strings.ToValidUTF8(username, "")
		username = strings.Trim(username, "\r")
		username = strings.Trim(username, "\n")
		if username == "" {
			continue
		}
		//queue <- username
		queue = append(queue, username)
	}

	// Start the workers
	for i := 0; i < options.Thread; i++ {
		wg.Add(1)
		/*
			reqcounter = append(reqcounter, 0)
			hpgid = append(hpgid, "")
			hpgact = append(hpgact, "")
			sCtx = append(sCtx, "")
			hpgrequestid = append(hpgrequestid, "")
			referer = append(referer, "")
		*/

		//worker function
		go func(threadindex int) {
			defer wg.Done()
			//for username := range queue {
			for len(queue) > 0 {
				mux.Lock()
				username := queue[0]
				queue[0] = ""
				queue = queue[1:]
				mux.Unlock()

				options.Log.Verbose("Testing " + username)

				if orchestrator.CheckBeforeEnumFunc != nil {
					// If the check did not pass for that user skip it
					if !orchestrator.CheckBeforeEnumFunc(&optionsInterface, username) {
						continue
					}
				}
				resbool, resint := orchestrator.UserEnumFunc(&optionsInterface, username, threadindex)
				mux.Lock()
				totalCount++
				mux.Unlock()
				if resbool {
					options.Log.Debug(username + " exists")
					mux.Lock()
					validUsers = append(validUsers, username)
					mux.Unlock()
				} else {
					if resint == 0 {
						options.Log.Debug(username + " does not exist")
					}
					if resint == 2 {
						mux.Lock()
						//add username to errorUsers
						errorUsers = append(errorUsers, username)
						errorCount++
						mux.Unlock()
					}
					if resint == 1 {
						options.Log.Info("[+/-]" + username + ": status unknown (throttled).")
						mux.Lock()
						//add username to throttledUsers
						throttledUsers = append(throttledUsers, username)
						throttledCont++
						mux.Unlock()
					}
				}
			}
		}(i)
	}

	//close(queue)
	// Wait all the workers
	wg.Wait()

	// Doing the post action
	if orchestrator.PostActionUserEnum != nil {
		if !orchestrator.PostActionUserEnum(&optionsInterface) {
			return strings.Join(validUsers, "\n")
		}
	}
	return strings.Join(validUsers, "\n") + strings.Join(throttledUsers, " - [+/-]\n")
}
