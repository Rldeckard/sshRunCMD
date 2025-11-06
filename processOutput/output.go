package output

import (
	"strings"
)

// Removes the banners from the output array to make the code easier to digest.
// Also looks for any errors in the execution.
func Process(input []string, originalOutput bool) ([]string, bool) {
	failedCommand := false
	for index, bannerString := range input {
		if originalOutput == false {
			if strings.Contains(bannerString, "-------------------------------") {
				input[index-1] = ""
				input[index] = ""
				input[index+1] = ""
			}
			if strings.Contains(bannerString, "terminal len") {
				input[index] = ""
			}
		}
		if strings.Contains(bannerString, "% Invalid") {
			failedCommand = true
		}
	}
	return input, failedCommand

}
