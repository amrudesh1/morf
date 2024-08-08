/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/package apk

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/amrudesh1/morf/models"

	util "github.com/amrudesh1/morf/utils"

	"github.com/lib/pq"
)

func ExtractPackageData(apkPath string) models.PackageDataModel {
	// Use AAPT to get APK Version etc
	// Check if AAPT is installed in the system or get aapt from the tools folder

	aapt_byte_to_string := util.RunAAPT(apkPath)[:]

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
	fmt.Println("Package Model:", packageModel.PackageName)
	return packageModel

}
