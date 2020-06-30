/*
Copyright 2017 The Kubernetes Authors.

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

package azure

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
	"github.com/stretchr/testify/assert"

	"k8s.io/legacy-cloud-providers/azure/retry"
)

func TestDecodePkcs12(t *testing.T) {
	p12Base64String := "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"
	data, err0 := base64.StdEncoding.DecodeString(p12Base64String)
	assert.NoError(t, err0)

	certificate, rsaPrivateKey, err := decodePkcs12(data,"123456")
	assert.NoError(t, err)
	assert.NotNil(t, certificate)
	assert.NotNil(t, rsaPrivateKey)

	certificate, rsaPrivateKey, err = decodePkcs12(data,"badpassword")
	assert.Nil(t, certificate)
	assert.Nil(t, rsaPrivateKey)
	assert.Equal(t, fmt.Errorf("decoding the PKCS#12 client certificate: pkcs12: decryption password incorrect"), err,"expect decode p12 file fail.")
}

func TestSplitBlobURI(t *testing.T) {
	expectedAccountName := "vhdstorage8h8pjybi9hbsl6"
	expectedContainerName := "vhds"
	expectedBlobPath := "osdisks/disk1234.vhd"
	accountName, containerName, blobPath, err := splitBlobURI("https://vhdstorage8h8pjybi9hbsl6.blob.core.windows.net/vhds/osdisks/disk1234.vhd")
	if accountName != expectedAccountName {
		t.Fatalf("incorrect account name. expected=%s actual=%s", expectedAccountName, accountName)
	}
	if containerName != expectedContainerName {
		t.Fatalf("incorrect account name. expected=%s actual=%s", expectedContainerName, containerName)
	}
	if blobPath != expectedBlobPath {
		t.Fatalf("incorrect account name. expected=%s actual=%s", expectedBlobPath, blobPath)
	}
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestK8sLinuxVMNameParts(t *testing.T) {
	data := []struct {
		poolIdentifier, nameSuffix string
		agentIndex                 int
	}{
		{"agentpool1", "38988164", 10},
		{"agent-pool1", "38988164", 8},
		{"agent-pool-1", "38988164", 0},
	}

	for _, el := range data {
		vmName := fmt.Sprintf("k8s-%s-%s-%d", el.poolIdentifier, el.nameSuffix, el.agentIndex)
		poolIdentifier, nameSuffix, agentIndex, err := k8sLinuxVMNameParts(vmName)
		if poolIdentifier != el.poolIdentifier {
			t.Fatalf("incorrect poolIdentifier. expected=%s actual=%s", el.poolIdentifier, poolIdentifier)
		}
		if nameSuffix != el.nameSuffix {
			t.Fatalf("incorrect nameSuffix. expected=%s actual=%s", el.nameSuffix, nameSuffix)
		}
		if agentIndex != el.agentIndex {
			t.Fatalf("incorrect agentIndex. expected=%d actual=%d", el.agentIndex, agentIndex)
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
}

func TestWindowsVMNameParts(t *testing.T) {
	data := []struct {
		VMName, expectedPoolPrefix, expectedOrch string
		expectedPoolIndex, expectedAgentIndex    int
	}{
		{"38988k8s90312", "38988", "k8s", 3, 12},
		{"4506k8s010", "4506", "k8s", 1, 0},
		{"2314k8s03000001", "2314", "k8s", 3, 1},
		{"2314k8s0310", "2314", "k8s", 3, 10},
	}

	for _, d := range data {
		poolPrefix, orch, poolIndex, agentIndex, err := windowsVMNameParts(d.VMName)
		if poolPrefix != d.expectedPoolPrefix {
			t.Fatalf("incorrect poolPrefix. expected=%s actual=%s", d.expectedPoolPrefix, poolPrefix)
		}
		if orch != d.expectedOrch {
			t.Fatalf("incorrect aks string. expected=%s actual=%s", d.expectedOrch, orch)
		}
		if poolIndex != d.expectedPoolIndex {
			t.Fatalf("incorrect poolIndex. expected=%d actual=%d", d.expectedPoolIndex, poolIndex)
		}
		if agentIndex != d.expectedAgentIndex {
			t.Fatalf("incorrect agentIndex. expected=%d actual=%d", d.expectedAgentIndex, agentIndex)
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
}

func TestGetVMNameIndexLinux(t *testing.T) {
	expectedAgentIndex := 65

	agentIndex, err := GetVMNameIndex(compute.Linux, "k8s-agentpool1-38988164-65")
	if agentIndex != expectedAgentIndex {
		t.Fatalf("incorrect agentIndex. expected=%d actual=%d", expectedAgentIndex, agentIndex)
	}
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestGetVMNameIndexWindows(t *testing.T) {
	expectedAgentIndex := 20

	agentIndex, err := GetVMNameIndex(compute.Windows, "38988k8s90320")
	if agentIndex != expectedAgentIndex {
		t.Fatalf("incorrect agentIndex. expected=%d actual=%d", expectedAgentIndex, agentIndex)
	}
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestIsSuccessResponse(t *testing.T) {
	tests := []struct {
		name          string
		resp          *http.Response
		err           error
		expected      bool
		expectedError error
	}{
		{
			name:          "both resp and err nil should report error",
			expected:      false,
			expectedError: fmt.Errorf("failed with unknown error"),
		},
		{
			name: "http.StatusNotFound should report error",
			resp: &http.Response{
				StatusCode: http.StatusNotFound,
			},
			expected:      false,
			expectedError: fmt.Errorf("failed with HTTP status code %d", http.StatusNotFound),
		},
		{
			name: "http.StatusInternalServerError should report error",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
			},
			expected:      false,
			expectedError: fmt.Errorf("failed with HTTP status code %d", http.StatusInternalServerError),
		},
		{
			name: "http.StatusOK shouldn't report error",
			resp: &http.Response{
				StatusCode: http.StatusOK,
			},
			expected: true,
		},
		{
			name: "non-nil response error with http.StatusOK should report error",
			resp: &http.Response{
				StatusCode: http.StatusOK,
			},
			err:           fmt.Errorf("test error"),
			expected:      false,
			expectedError: fmt.Errorf("test error"),
		},
		{
			name: "non-nil response error with http.StatusInternalServerError should report error",
			resp: &http.Response{
				StatusCode: http.StatusInternalServerError,
			},
			err:           fmt.Errorf("test error"),
			expected:      false,
			expectedError: fmt.Errorf("test error"),
		},
	}

	for _, test := range tests {
		result, realError := isSuccessHTTPResponse(test.resp, test.err)
		assert.Equal(t, test.expected, result, "[%s] expected: %v, saw: %v", test.name, result, test.expected)
		assert.Equal(t, test.expectedError, realError, "[%s] expected: %v, saw: %v", test.name, realError, test.expectedError)
	}
}
func TestConvertResourceGroupNameToLower(t *testing.T) {
	tests := []struct {
		desc        string
		resourceID  string
		expected    string
		expectError bool
	}{
		{
			desc:        "empty string should report error",
			resourceID:  "",
			expectError: true,
		},
		{
			desc:        "resourceID not in Azure format should report error",
			resourceID:  "invalid-id",
			expectError: true,
		},
		{
			desc:        "providerID not in Azure format should report error",
			resourceID:  "azure://invalid-id",
			expectError: true,
		},
		{
			desc:       "resource group name in VM providerID should be converted",
			resourceID: "azure:///subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroupName/providers/Microsoft.Compute/virtualMachines/k8s-agent-AAAAAAAA-0",
			expected:   "azure:///subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myresourcegroupname/providers/Microsoft.Compute/virtualMachines/k8s-agent-AAAAAAAA-0",
		},
		{
			desc:       "resource group name in VM resourceID should be converted",
			resourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroupName/providers/Microsoft.Compute/virtualMachines/k8s-agent-AAAAAAAA-0",
			expected:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myresourcegroupname/providers/Microsoft.Compute/virtualMachines/k8s-agent-AAAAAAAA-0",
		},
		{
			desc:       "resource group name in VMSS providerID should be converted",
			resourceID: "azure:///subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroupName/providers/Microsoft.Compute/virtualMachineScaleSets/myScaleSetName/virtualMachines/156",
			expected:   "azure:///subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myresourcegroupname/providers/Microsoft.Compute/virtualMachineScaleSets/myScaleSetName/virtualMachines/156",
		},
		{
			desc:       "resource group name in VMSS resourceID should be converted",
			resourceID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroupName/providers/Microsoft.Compute/virtualMachineScaleSets/myScaleSetName/virtualMachines/156",
			expected:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myresourcegroupname/providers/Microsoft.Compute/virtualMachineScaleSets/myScaleSetName/virtualMachines/156",
		},
	}

	for _, test := range tests {
		real, err := convertResourceGroupNameToLower(test.resourceID)
		if test.expectError {
			assert.NotNil(t, err, test.desc)
			continue
		}

		assert.Nil(t, err, test.desc)
		assert.Equal(t, test.expected, real, test.desc)
	}
}

func TestIsAzureRequestsThrottled(t *testing.T) {
	tests := []struct {
		desc     string
		rerr     *retry.Error
		expected bool
	}{
		{
			desc:     "nil error should return false",
			expected: false,
		},
		{
			desc: "non http.StatusTooManyRequests error should return false",
			rerr: &retry.Error{
				HTTPStatusCode: http.StatusBadRequest,
			},
			expected: false,
		},
		{
			desc: "http.StatusTooManyRequests error should return true",
			rerr: &retry.Error{
				HTTPStatusCode: http.StatusTooManyRequests,
			},
			expected: true,
		},
	}

	for _, test := range tests {
		real := isAzureRequestsThrottled(test.rerr)
		assert.Equal(t, test.expected, real, test.desc)
	}
}
