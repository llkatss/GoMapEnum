package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

func (logger *Logger) print(str string) {
	var output string
	var foutput string
	if logger.NoColor {
		output = logger.Mode + "\t\t" + logger.Module + "\t\t" + logger.Target + "\t\t" + str + "\n"
		foutput = output
	} else {
		output = color.HiCyanString(logger.Mode+"\t\t"+logger.Module) + "\t\t" + logger.Target + "\t\t" + str + "\n"
		foutput = logger.Mode + "\t\t" + logger.Module + "\t\t" + logger.Target + "\t\t" + str + "\n"
	}
	//fmt.Println(output)
	// For Linux and Windows support of colored output
	fmt.Fprint(color.Output, output)
	if logger.File != "" {
		f, err := os.OpenFile(logger.File, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			logger.File = ""
			logger.Error("Fail to open " + logger.File + ": " + err.Error())
			return
		}

		defer f.Close()
		foutput = strings.ReplaceAll(foutput, "\t\t", ";")
		now := time.Now().Local()
		if _, err = f.WriteString(now.Local().String() + ";" + foutput); err != nil {
			logger.File = ""
			logger.Error("Fail to write into " + logger.File + ": " + err.Error())
			return
		}
	}

}
