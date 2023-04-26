package apk

import (
	"morf/models"
	util "morf/utils"
	"os/exec"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/lib/pq"
)

func ExtractPackageData(apkPath string) models.PackageDataModel {
	// Use AAPT to get APK Version etc
	aapt_success, aapt_error := exec.Command("aapt", "dump", "badging", apkPath).Output()

	if aapt_error != nil {
		log.Error("Error while getting APK version etc")
		log.Fatal(aapt_error)
	}

	aapt_byte_to_string := aapt_success[:]
	aapt_split_stirng := strings.Split(string(aapt_byte_to_string), "\n")
	re := regexp.MustCompile(`'[^"]+'`)
	package_name := ""
	version_code := ""
	version_name := ""
	complie_sdk_version := ""
	sdk_version := ""
	target_sdk := ""
	support_screens := []string{}
	densities := []string{}
	native_code := []string{}

	for _, value := range aapt_split_stirng {
		// fmt.Println(value)
		if strings.Contains(value, "package") {

			package_name_extracted := strings.Split(value, " ")[1]
			newStrs := re.FindAllString(package_name_extracted, -1)
			if len(newStrs) > 0 {
				package_name = strings.Replace(newStrs[0], "'", "", -1)
			}

			version_code_extracted := strings.Split(value, " ")[2]
			newStrs = re.FindAllString(version_code_extracted, -1)
			if len(newStrs) > 0 {
				version_code = strings.Replace(newStrs[0], "'", "", -1)
			}

			version_name_extracted := strings.Split(value, " ")[3]
			newStrs = re.FindAllString(version_name_extracted, -1)
			if len(newStrs) > 0 {
				version_name = strings.Replace(newStrs[0], "'", "", -1)
			}

			complie_sdk_version_extracted := strings.Split(value, " ")[4]
			newStrs = re.FindAllString(complie_sdk_version_extracted, -1)
			if len(newStrs) > 0 {
				complie_sdk_version = strings.Replace(newStrs[0], "'", "", -1)
			}

		}

		if strings.Contains(value, "sdkVersion") {
			sdk_version_extracted := strings.Split(value, ":")[1]
			newStrs := re.FindAllString(sdk_version_extracted, -1)
			sdk_version = strings.Replace(newStrs[0], "'", "", -1)
		}

		if strings.Contains(value, "targetSdkVersion") {
			target_sdk_version_extracted := strings.Split(value, ":")[1]
			newStrs := re.FindAllString(target_sdk_version_extracted, -1)
			target_sdk = strings.Replace(newStrs[0], "'", "", -1)

		}

		if strings.Contains(value, "supports-screens") {
			support_screens_extracted := strings.Split(value, ":")[1]
			newStrs := re.FindAllString(support_screens_extracted, -1)
			for _, value := range newStrs {
				value = strings.Replace(value, "'", "", -1)
				support_screens = strings.Split(value, " ")
			}
		}

		if strings.Contains(value, "densities") {
			densities_extracted := strings.Split(value, ":")[1]
			newStrs := re.FindAllString(densities_extracted, -1)
			for _, value := range newStrs {
				value = strings.Replace(value, "'", "", -1)
				densities = strings.Split(value, " ")
			}
		}

		if strings.Contains(value, "native-code") {
			native_code_extracted := strings.Split(value, ":")[1]
			newStrs := re.FindAllString(native_code_extracted, -1)
			for _, value := range newStrs {
				value = strings.Replace(value, "'", "", -1)
				native_code = strings.Split(value, " ")

			}
		}

	}
	packageModel := models.PackageDataModel{PackageDataID: 0, APKHash: util.ExtractHash(apkPath), PackageName: package_name, VersionCode: version_code, VersionName: version_name, CompileSdkVersion: complie_sdk_version, SdkVersion: sdk_version, TargetSdk: target_sdk, SupportScreens: pq.StringArray(support_screens), Densities: pq.StringArray(densities), NativeCode: pq.StringArray(native_code)}
	return packageModel

}
