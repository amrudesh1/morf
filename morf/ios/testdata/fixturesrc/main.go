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

// Command fixturesrc is a deliberately minimal, license-clean program that is
// cross-compiled into an arm64 Mach-O binary used as an iOS scanning test
// fixture for MORF.
//
// It intentionally embeds two well-known *fake* secret strings so that the
// MORF secret scanner (and the go-macho string extraction path) have concrete,
// deterministic hits to assert against:
//
//   - AKIAIOSFODNN7EXAMPLE  -> matches the "AWS API Key" pattern (AKIA[0-9A-Z]{16}).
//     This is AWS's own published, non-functional example access key ID.
//   - sk_live_MASKED_FIXTURE -> matches the "Stripe API Key"
//     pattern (sk_live_[0-9a-zA-Z]{24}). The 24-char body is fabricated and
//     corresponds to no real Stripe account.
//
// Neither value grants access to anything; both exist purely so tests can
// verify that a planted secret in a real Mach-O binary is discovered.
package main

import "fmt"

// fakeAWSKey is a non-functional AWS example access key ID (see AWS docs).
// It exists only so the scanner has a deterministic "AWS API Key" hit.
const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

// fakeStripeKey is a fabricated Stripe-style live key. The 24-character body
// is not tied to any real account; it exists only to trigger the
// "Stripe API Key" pattern (sk_live_[0-9a-zA-Z]{24}).
const fakeStripeKey = "sk_live_MASKED_FIXTURE"

func main() {
	// Reference both constants so the linker keeps the strings in __TEXT.
	fmt.Println("morf ios fixture binary")
	fmt.Println(fakeAWSKey)
	fmt.Println(fakeStripeKey)
}
