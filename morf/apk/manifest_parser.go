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
*/

package apk

import (
	"fmt"
	"morf/models"
	"morf/utils"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ExtractComponentExportInfo extracts export information for components from the APK manifest
func ExtractComponentExportInfo(apkPath string, metadata *models.MetaDataModel) {
	log.Info("Starting component extraction from manifest")

	// Extract activities, services, receivers, and providers from the manifest
	xmlTree, err := utils.ExecuteCommand("aapt", "dump", "xmltree", apkPath, "AndroidManifest.xml")
	if err != nil {
		log.Error("Error extracting manifest XML tree:", err)
		setDefaultExportedValues(metadata)
		return
	}

	log.Debug("Successfully dumped manifest XML tree")

	// Parse the XML tree to extract component information
	targetSdk, _ := strconv.Atoi(metadata.AndroidManifest.UsesTargetSdkVersion)
	log.Infof("Target SDK version: %d", targetSdk)

	// Extract activities
	log.Debug("Extracting activities...")
	activities := extractActivities(xmlTree, targetSdk)
	metadata.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo](activities)

	// Extract services
	log.Debug("Extracting services...")
	services := extractServices(xmlTree, targetSdk)
	metadata.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo](services)

	// Extract broadcast receivers
	log.Debug("Extracting broadcast receivers...")
	receivers := extractReceivers(xmlTree, targetSdk)
	metadata.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo](receivers)

	// Extract content providers
	log.Debug("Extracting content providers...")
	providers := extractProviders(xmlTree, targetSdk)
	metadata.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo](providers)

	// Log component counts for debugging
	log.Infof("Extracted %d activities", len(activities))
	log.Infof("Extracted %d services", len(services))
	log.Infof("Extracted %d receivers", len(receivers))
	log.Infof("Extracted %d providers", len(providers))

	// Log deeplink information
	deeplinkCount := 0
	for _, activity := range activities {
		for _, filter := range activity.IntentFilters {
			for _, data := range filter.Data {
				if data.Scheme != "" {
					deeplinkCount++
					log.Infof("Found deeplink in %s: scheme=%s, host=%s, path=%s, pathPattern=%s",
						activity.Name, data.Scheme, data.Host, data.Path, data.PathPattern)

					// Log if this is an app link (https scheme with autoVerify)
					if data.Scheme == "https" && filter.AutoVerify {
						log.Infof("App Link found: %s://%s%s", data.Scheme, data.Host, data.Path)
					}
				}
			}
		}
	}
	log.Infof("Total deeplinks found: %d", deeplinkCount)
}

// setDefaultExportedValues sets default exported values for components
func setDefaultExportedValues(metadata *models.MetaDataModel) {
	// Set default values for activities
	activities := make([]models.ManifestActivityInfo, len(metadata.AndroidManifest.Activities))
	for i := range activities {
		activities[i] = models.ManifestActivityInfo{
			Name:     metadata.AndroidManifest.Activities[i].Name,
			Exported: false, // Default to false for security
		}
	}
	metadata.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo](activities)

	// Set default values for services
	services := make([]models.ManifestServiceInfo, len(metadata.AndroidManifest.Services))
	for i := range services {
		services[i] = models.ManifestServiceInfo{
			Name:     metadata.AndroidManifest.Services[i].Name,
			Exported: false, // Default to false for security
		}
	}
	metadata.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo](services)

	// Set default values for broadcast receivers
	receivers := make([]models.ManifestReceiverInfo, len(metadata.AndroidManifest.BroadcastReceivers))
	for i := range receivers {
		receivers[i] = models.ManifestReceiverInfo{
			Name:     metadata.AndroidManifest.BroadcastReceivers[i].Name,
			Exported: false, // Default to false for security
		}
	}
	metadata.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo](receivers)

	// Set default values for content providers
	providers := make([]models.ManifestProviderInfo, len(metadata.AndroidManifest.ContentProviders))
	for i := range providers {
		providers[i] = models.ManifestProviderInfo{
			Name:     metadata.AndroidManifest.ContentProviders[i].Name,
			Exported: false, // Default to false for security
		}
	}
	metadata.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo](providers)
}

// isHexValueTrue checks if a hex value string represents true (0xffffffff)
func isHexValueTrue(hexValue string) bool {
	return hexValue == "0xffffffff"
}

// extractActivities extracts activity information from the manifest XML tree
func extractActivities(xmlTree string, targetSdk int) []models.ManifestActivityInfo {
	activities := make([]models.ManifestActivityInfo, 0)

	// Split the XML tree by activity tags
	log.Debug("Extracting activity blocks from manifest...")
	activityBlocks := extractComponentBlocks(xmlTree, "activity")
	log.Debugf("Found %d activity blocks", len(activityBlocks))

	for i, block := range activityBlocks {
		log.Debugf("Processing activity block %d/%d", i+1, len(activityBlocks))

		// Extract activity name
		nameMatch := regexp.MustCompile(`android:name\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(nameMatch) < 2 {
			log.Debug("Skipping activity block without name attribute")
			continue
		}

		activityName := nameMatch[1]
		log.Debugf("Found activity: %s", activityName)

		// Check if explicitly exported
		exported := false

		// Check for string format: android:exported="true"
		exportedStringMatch := regexp.MustCompile(`android:exported\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(exportedStringMatch) >= 2 {
			exported = exportedStringMatch[1] == "true"
			log.Debugf("Activity %s has explicit string exported=%v", activityName, exported)
		} else {
			// Check for hex format: android:exported(0x01010010)=(type 0x12)0xffffffff
			exportedHexMatch := regexp.MustCompile(`android:exported\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(block)
			if len(exportedHexMatch) >= 2 {
				exported = isHexValueTrue(exportedHexMatch[1])
				log.Debugf("Activity %s has explicit hex exported=%v (%s)", activityName, exported, exportedHexMatch[1])
			} else {
				// If not explicitly set, check for intent filters
				// For Android 12+ (SDK 31+), components with intent filters are not automatically exported
				hasIntentFilter := strings.Contains(block, "E: intent-filter")
				exported = hasIntentFilter && targetSdk < 31
				if hasIntentFilter {
					log.Debugf("Activity %s has intent filters, exported=%v (targetSdk=%d)",
						activityName, exported, targetSdk)
				} else {
					log.Debugf("Activity %s has no intent filters, exported=false", activityName)
				}
			}
		}

		// Extract intent filters
		log.Debugf("Extracting intent filters for activity: %s", activityName)
		intentFilters := extractIntentFilters(block)
		log.Debugf("Found %d intent filters for activity: %s", len(intentFilters), activityName)

		activity := models.ManifestActivityInfo{
			Name:          activityName,
			Exported:      exported,
			IntentFilters: intentFilters,
		}
		activities = append(activities, activity)

		// Log activity details
		log.Debugf("Activity details - Name: %s, Exported: %v, Intent Filters: %d",
			activity.Name, activity.Exported, len(activity.IntentFilters))
	}

	return activities
}

// extractServices extracts service information from the manifest XML tree
func extractServices(xmlTree string, targetSdk int) []models.ManifestServiceInfo {
	services := make([]models.ManifestServiceInfo, 0)

	// Split the XML tree by service tags
	log.Debug("Extracting service blocks from manifest...")
	serviceBlocks := extractComponentBlocks(xmlTree, "service")
	log.Debugf("Found %d service blocks", len(serviceBlocks))

	for i, block := range serviceBlocks {
		log.Debugf("Processing service block %d/%d", i+1, len(serviceBlocks))

		// Extract service name
		nameMatch := regexp.MustCompile(`android:name\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(nameMatch) < 2 {
			log.Debug("Skipping service block without name attribute")
			continue
		}

		serviceName := nameMatch[1]
		log.Debugf("Found service: %s", serviceName)

		// Check if explicitly exported
		exported := false

		// Check for string format: android:exported="true"
		exportedStringMatch := regexp.MustCompile(`android:exported\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(exportedStringMatch) >= 2 {
			exported = exportedStringMatch[1] == "true"
			log.Debugf("Service %s has explicit string exported=%v", serviceName, exported)
		} else {
			// Check for hex format: android:exported(0x01010010)=(type 0x12)0xffffffff
			exportedHexMatch := regexp.MustCompile(`android:exported\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(block)
			if len(exportedHexMatch) >= 2 {
				exported = isHexValueTrue(exportedHexMatch[1])
				log.Debugf("Service %s has explicit hex exported=%v (%s)", serviceName, exported, exportedHexMatch[1])
			} else {
				// If not explicitly set, check for intent filters
				// For Android 12+ (SDK 31+), components with intent filters are not automatically exported
				hasIntentFilter := strings.Contains(block, "E: intent-filter")
				exported = hasIntentFilter && targetSdk < 31
				if hasIntentFilter {
					log.Debugf("Service %s has intent filters, exported=%v (targetSdk=%d)",
						serviceName, exported, targetSdk)
				} else {
					log.Debugf("Service %s has no intent filters, exported=false", serviceName)
				}
			}
		}

		// Extract intent filters
		log.Debugf("Extracting intent filters for service: %s", serviceName)
		intentFilters := extractIntentFilters(block)
		log.Debugf("Found %d intent filters for service: %s", len(intentFilters), serviceName)

		service := models.ManifestServiceInfo{
			Name:          serviceName,
			Exported:      exported,
			IntentFilters: intentFilters,
		}
		services = append(services, service)

		// Log service details
		log.Debugf("Service details - Name: %s, Exported: %v, Intent Filters: %d",
			service.Name, service.Exported, len(service.IntentFilters))
	}

	return services
}

// extractReceivers extracts broadcast receiver information from the manifest XML tree
func extractReceivers(xmlTree string, targetSdk int) []models.ManifestReceiverInfo {
	receivers := make([]models.ManifestReceiverInfo, 0)

	// Split the XML tree by receiver tags
	log.Debug("Extracting receiver blocks from manifest...")
	receiverBlocks := extractComponentBlocks(xmlTree, "receiver")
	log.Debugf("Found %d receiver blocks", len(receiverBlocks))

	for i, block := range receiverBlocks {
		log.Debugf("Processing receiver block %d/%d", i+1, len(receiverBlocks))

		// Extract receiver name
		nameMatch := regexp.MustCompile(`android:name\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(nameMatch) < 2 {
			log.Debug("Skipping receiver block without name attribute")
			continue
		}

		receiverName := nameMatch[1]
		log.Debugf("Found receiver: %s", receiverName)

		// Check if explicitly exported
		exported := false

		// Check for string format: android:exported="true"
		exportedStringMatch := regexp.MustCompile(`android:exported\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(exportedStringMatch) >= 2 {
			exported = exportedStringMatch[1] == "true"
			log.Debugf("Receiver %s has explicit string exported=%v", receiverName, exported)
		} else {
			// Check for hex format: android:exported(0x01010010)=(type 0x12)0xffffffff
			exportedHexMatch := regexp.MustCompile(`android:exported\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(block)
			if len(exportedHexMatch) >= 2 {
				exported = isHexValueTrue(exportedHexMatch[1])
				log.Debugf("Receiver %s has explicit hex exported=%v (%s)", receiverName, exported, exportedHexMatch[1])
			} else {
				// If not explicitly set, check for intent filters
				// For Android 12+ (SDK 31+), components with intent filters are not automatically exported
				hasIntentFilter := strings.Contains(block, "E: intent-filter")
				exported = hasIntentFilter && targetSdk < 31
				if hasIntentFilter {
					log.Debugf("Receiver %s has intent filters, exported=%v (targetSdk=%d)",
						receiverName, exported, targetSdk)
				} else {
					log.Debugf("Receiver %s has no intent filters, exported=false", receiverName)
				}
			}
		}

		// Extract intent filters
		log.Debugf("Extracting intent filters for receiver: %s", receiverName)
		intentFilters := extractIntentFilters(block)
		log.Debugf("Found %d intent filters for receiver: %s", len(intentFilters), receiverName)

		receiver := models.ManifestReceiverInfo{
			Name:          receiverName,
			Exported:      exported,
			IntentFilters: intentFilters,
		}
		receivers = append(receivers, receiver)

		// Log receiver details
		log.Debugf("Receiver details - Name: %s, Exported: %v, Intent Filters: %d",
			receiver.Name, receiver.Exported, len(receiver.IntentFilters))
	}

	return receivers
}

// extractProviders extracts content provider information from the manifest XML tree
func extractProviders(xmlTree string, targetSdk int) []models.ManifestProviderInfo {
	providers := make([]models.ManifestProviderInfo, 0)

	// Split the XML tree by provider tags
	log.Debug("Extracting provider blocks from manifest...")
	providerBlocks := extractComponentBlocks(xmlTree, "provider")
	log.Debugf("Found %d provider blocks", len(providerBlocks))

	for i, block := range providerBlocks {
		log.Debugf("Processing provider block %d/%d", i+1, len(providerBlocks))

		// Extract provider name
		nameMatch := regexp.MustCompile(`android:name\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(nameMatch) < 2 {
			log.Debug("Skipping provider block without name attribute")
			continue
		}

		providerName := nameMatch[1]
		log.Debugf("Found provider: %s", providerName)

		// Check if explicitly exported
		exported := false

		// Check for string format: android:exported="true"
		exportedStringMatch := regexp.MustCompile(`android:exported\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		if len(exportedStringMatch) >= 2 {
			exported = exportedStringMatch[1] == "true"
			log.Debugf("Provider %s has explicit string exported=%v", providerName, exported)
		} else {
			// Check for hex format: android:exported(0x01010010)=(type 0x12)0xffffffff
			exportedHexMatch := regexp.MustCompile(`android:exported\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(block)
			if len(exportedHexMatch) >= 2 {
				exported = isHexValueTrue(exportedHexMatch[1])
				log.Debugf("Provider %s has explicit hex exported=%v (%s)", providerName, exported, exportedHexMatch[1])
			} else {
				// For providers, the default is false unless android:grantUriPermissions is true
				// Check for string format first
				grantUriStringMatch := regexp.MustCompile(`android:grantUriPermissions\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
				if len(grantUriStringMatch) >= 2 {
					exported = grantUriStringMatch[1] == "true"
					log.Debugf("Provider %s has string grantUriPermissions=%v", providerName, exported)
				} else {
					// Check for hex format
					grantUriHexMatch := regexp.MustCompile(`android:grantUriPermissions\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(block)
					if len(grantUriHexMatch) >= 2 {
						exported = isHexValueTrue(grantUriHexMatch[1])
						log.Debugf("Provider %s has hex grantUriPermissions=%v (%s)", providerName, exported, grantUriHexMatch[1])
					} else {
						log.Debugf("Provider %s has no explicit export setting and no grantUriPermissions, defaulting to exported=false", providerName)
					}
				}
			}
		}

		// Extract authorities
		authoritiesMatch := regexp.MustCompile(`android:authorities\(.*?\)="([^"]+)"`).FindStringSubmatch(block)
		var authorities []string
		if len(authoritiesMatch) >= 2 {
			authorities = strings.Split(authoritiesMatch[1], ";")
			log.Debugf("Found authorities for provider %s: %v", providerName, authorities)
		} else {
			log.Debugf("No authorities found for provider %s", providerName)
		}

		provider := models.ManifestProviderInfo{
			Name:        providerName,
			Exported:    exported,
			Authorities: authorities,
		}
		providers = append(providers, provider)

		// Log provider details
		log.Debugf("Provider details - Name: %s, Exported: %v, Authorities: %d",
			provider.Name, provider.Exported, len(provider.Authorities))
	}

	return providers
}

// extractIntentFilters extracts intent filter information from a component block
func extractIntentFilters(block string) []models.ManifestFilter {
	filters := make([]models.ManifestFilter, 0)

	// Split the block into lines
	lines := strings.Split(block, "\n")
	var currentFilterBlock []string
	inFilterBlock := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Check if this is the start of an intent filter block
		if strings.Contains(line, "E: intent-filter") {
			// Start a new filter block
			currentFilterBlock = []string{line}
			inFilterBlock = true
			continue
		}

		// If we're in a filter block and this line is indented, add it to the current block
		if inFilterBlock {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				currentFilterBlock = append(currentFilterBlock, line)
			} else if line == "" {
				// Empty lines are okay within blocks
				currentFilterBlock = append(currentFilterBlock, line)
			} else {
				// Non-indented, non-empty line means end of filter block
				// Process the completed filter block
				filter := processIntentFilterBlock(strings.Join(currentFilterBlock, "\n"))
				if filter != nil {
					filters = append(filters, *filter)
					log.Debugf("Found intent filter with %d actions, %d categories, %d data elements",
						len(filter.Actions), len(filter.Categories), len(filter.Data))
				}
				inFilterBlock = false

				// If this is the start of another element, process it in the next iteration
				if strings.HasPrefix(line, "E: ") {
					i-- // Back up one line
				}
			}
		}
	}

	// Don't forget to process the last filter block if we were still in one
	if inFilterBlock && len(currentFilterBlock) > 0 {
		filter := processIntentFilterBlock(strings.Join(currentFilterBlock, "\n"))
		if filter != nil {
			filters = append(filters, *filter)
			log.Debugf("Found intent filter with %d actions, %d categories, %d data elements",
				len(filter.Actions), len(filter.Categories), len(filter.Data))
		}
	}

	return filters
}

// processIntentFilterBlock processes a single intent filter block and extracts its data
func processIntentFilterBlock(filterBlock string) *models.ManifestFilter {
	filter := &models.ManifestFilter{}

	// Check for autoVerify attribute - string format
	autoVerifyStringMatch := regexp.MustCompile(`android:autoVerify\(.*?\)="([^"]+)"`).FindStringSubmatch(filterBlock)
	if len(autoVerifyStringMatch) >= 2 && autoVerifyStringMatch[1] == "true" {
		filter.AutoVerify = true
	} else {
		// Check for autoVerify attribute - hex format
		autoVerifyHexMatch := regexp.MustCompile(`android:autoVerify\(.*?\)=\(type [^)]+\)(0x[0-9a-f]+)`).FindStringSubmatch(filterBlock)
		if len(autoVerifyHexMatch) >= 2 {
			filter.AutoVerify = isHexValueTrue(autoVerifyHexMatch[1])
		}
	}

	// Extract actions
	actionPattern := `(?m)^[ \t]*E: action[^\n]*\n[ \t]*A: android:name\(.*?\)="([^"]+)"`
	actionRegex := regexp.MustCompile(actionPattern)
	actionMatches := actionRegex.FindAllStringSubmatch(filterBlock, -1)
	for _, actionMatch := range actionMatches {
		if len(actionMatch) >= 2 {
			filter.Actions = append(filter.Actions, actionMatch[1])
		}
	}

	// Extract categories
	categoryPattern := `(?m)^[ \t]*E: category[^\n]*\n[ \t]*A: android:name\(.*?\)="([^"]+)"`
	categoryRegex := regexp.MustCompile(categoryPattern)
	categoryMatches := categoryRegex.FindAllStringSubmatch(filterBlock, -1)
	for _, categoryMatch := range categoryMatches {
		if len(categoryMatch) >= 2 {
			filter.Categories = append(filter.Categories, categoryMatch[1])
		}
	}

	// Extract data elements
	// Split the block into lines to find data blocks
	lines := strings.Split(filterBlock, "\n")
	var currentDataBlock []string
	inDataBlock := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Check if this is the start of a data block
		if strings.Contains(line, "E: data") {
			// If we were already in a data block, process it
			if inDataBlock && len(currentDataBlock) > 0 {
				processDataBlock(strings.Join(currentDataBlock, "\n"), filter)
			}
			// Start a new data block
			currentDataBlock = []string{line}
			inDataBlock = true
			continue
		}

		// If we're in a data block and this line is indented, add it to the current block
		if inDataBlock {
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t\t") {
				currentDataBlock = append(currentDataBlock, line)
			} else {
				// End of data block
				processDataBlock(strings.Join(currentDataBlock, "\n"), filter)
				inDataBlock = false

				// If this is the start of another element, process it in the next iteration
				if strings.HasPrefix(line, "E: ") {
					i-- // Back up one line
				}
			}
		}
	}

	// Process the last data block if we were still in one
	if inDataBlock && len(currentDataBlock) > 0 {
		processDataBlock(strings.Join(currentDataBlock, "\n"), filter)
	}

	// Extract priority
	if priority := extractAttribute(filterBlock, "priority"); priority != "" {
		if p, err := strconv.Atoi(priority); err == nil {
			filter.Priority = p
		}
	}

	// Only return the filter if it has at least actions, categories, or data
	if len(filter.Actions) > 0 || len(filter.Data) > 0 || len(filter.Categories) > 0 {
		return filter
	}

	return nil
}

// processDataBlock processes a single data block and adds its data to the filter
func processDataBlock(dataBlock string, filter *models.ManifestFilter) {
	filterData := models.ManifestFilterData{}

	// Extract scheme
	if scheme := extractAttribute(dataBlock, "scheme"); scheme != "" {
		filterData.Scheme = scheme
	}

	// Extract host
	if host := extractAttribute(dataBlock, "host"); host != "" {
		filterData.Host = host
	}

	// Extract port
	if port := extractAttribute(dataBlock, "port"); port != "" {
		filterData.Port = port
	}

	// Extract path
	if path := extractAttribute(dataBlock, "path"); path != "" {
		filterData.Path = path
	}

	// Extract pathPattern
	if pattern := extractAttribute(dataBlock, "pathPattern"); pattern != "" {
		filterData.PathPattern = pattern
	}

	// Extract pathPrefix
	if prefix := extractAttribute(dataBlock, "pathPrefix"); prefix != "" {
		filterData.PathPrefix = append(filterData.PathPrefix, prefix)
	}

	// Extract mimeType
	if mimeType := extractAttribute(dataBlock, "mimeType"); mimeType != "" {
		filterData.MimeType = mimeType
	}

	// Only add data if we have at least one field set
	if filterData.Scheme != "" || filterData.Host != "" || filterData.Path != "" ||
		filterData.PathPattern != "" || len(filterData.PathPrefix) > 0 || filterData.MimeType != "" {
		filter.Data = append(filter.Data, filterData)
	}
}

// extractAttribute extracts an attribute value from a block
func extractAttribute(block string, attrName string) string {
	// Try string format first
	pattern := `android:` + attrName + `\(.*?\)="([^"]+)"`
	regex := regexp.MustCompile(pattern)
	match := regex.FindStringSubmatch(block)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}

// extractComponentBlocks extracts component blocks from the XML tree
func extractComponentBlocks(xmlTree string, componentType string) []string {
	var blocks []string

	// Split the XML tree into lines
	lines := strings.Split(xmlTree, "\n")
	var currentBlock []string
	inBlock := false
	inApplication := false
	applicationIndent := -1 // Use -1 to indicate we haven't found application yet
	componentIndent := -1   // Use -1 to indicate we're not in a component

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t") // Remove trailing whitespace
		if line == "" {
			continue // Skip empty lines
		}

		indent := countLeadingSpaces(line)
		trimmedLine := strings.TrimSpace(line)

		// Track if we're inside the application block
		if strings.HasPrefix(trimmedLine, "E: application") {
			inApplication = true
			applicationIndent = indent
			continue
		}

		// Check if we've exited the application block
		// Only exit if we find another element at the same level as application
		if inApplication && indent <= applicationIndent && strings.HasPrefix(trimmedLine, "E:") {
			if indent == applicationIndent {
				inApplication = false
				applicationIndent = -1
			}
			continue
		}

		// Skip if we're not in the application block
		if !inApplication {
			continue
		}

		// Check if this is the start of our target component type
		if strings.HasPrefix(trimmedLine, fmt.Sprintf("E: %s", componentType)) {
			// If we were already in a block, save it
			if inBlock && len(currentBlock) > 0 {
				block := strings.Join(currentBlock, "\n")
				if strings.Contains(block, "android:name") {
					blocks = append(blocks, block)
					log.Debugf("Found %s block:\n%s", componentType, block)
				}
			}
			// Start a new block
			currentBlock = []string{line}
			inBlock = true
			componentIndent = indent
			continue
		}

		// If we're in a block, check if this line belongs to it
		if inBlock {
			// Add lines that are:
			// 1. More indented than the component start
			// 2. Empty lines within the block
			// 3. At the same level but not starting a new element
			if indent > componentIndent ||
				(indent == componentIndent && !strings.HasPrefix(trimmedLine, "E:")) {
				currentBlock = append(currentBlock, line)
			} else {
				// We've reached the end of this block
				// Only save if it has a name attribute
				block := strings.Join(currentBlock, "\n")
				if strings.Contains(block, "android:name") {
					blocks = append(blocks, block)
					log.Debugf("Found %s block:\n%s", componentType, block)
				}
				inBlock = false
				componentIndent = -1
				i-- // Back up to process this line again
			}
		}
	}

	// Process the last block if we were still in one
	if inBlock && len(currentBlock) > 0 {
		block := strings.Join(currentBlock, "\n")
		if strings.Contains(block, "android:name") {
			blocks = append(blocks, block)
			log.Debugf("Found %s block:\n%s", componentType, block)
		}
	}

	return blocks
}

// countLeadingSpaces counts the number of leading spaces in a string
func countLeadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t"))
}
