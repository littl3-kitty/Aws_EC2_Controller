package core

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var RegionNames = map[string]string{
	"us-east-1":      "N. Virginia",
	"us-east-2":      "Ohio",
	"us-west-1":      "N. California",
	"us-west-2":      "Oregon",
	"ap-south-1":     "Mumbai",
	"ap-northeast-1": "Tokyo",
	"ap-northeast-2": "Seoul",
	"ap-northeast-3": "Osaka",
	"ap-southeast-1": "Singapore",
	"ap-southeast-2": "Sydney",
	"ca-central-1":   "Canada",
	"eu-central-1":   "Frankfurt",
	"eu-west-1":      "Ireland",
	"eu-west-2":      "London",
	"eu-west-3":      "Paris",
	"eu-north-1":     "Stockholm",
}

type Instance struct {
	ID                    string
	Name                  string
	Status                string
	InstanceType          string
	Region                string
	TerminationProtection bool
	StopProtection        bool
}

type EC2Manager struct {
	accessKey string
	secretKey string
	clients   map[string]*ec2.Client
	mu        sync.RWMutex
}

func NewEC2Manager(accessKey, secretKey string) *EC2Manager {
	return &EC2Manager{
		accessKey: accessKey,
		secretKey: secretKey,
		clients:   make(map[string]*ec2.Client),
	}
}

func (m *EC2Manager) getClient(region string) (*ec2.Client, error) {
	m.mu.RLock()
	if client, ok := m.clients[region]; ok {
		m.mu.RUnlock()
		return client, nil
	}
	m.mu.RUnlock()

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			m.accessKey,
			m.secretKey,
			"",
		)),
	)
	if err != nil {
		return nil, err
	}

	client := ec2.NewFromConfig(cfg)
	
	m.mu.Lock()
	m.clients[region] = client
	m.mu.Unlock()

	return client, nil
}

func (m *EC2Manager) GetAvailableRegions() ([]string, error) {
	client, err := m.getClient("us-east-1")
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}

	regions := make([]string, 0, len(result.Regions))
	for _, r := range result.Regions {
		regions = append(regions, *r.RegionName)
	}

	return regions, nil
}

func (m *EC2Manager) GetInstancesInRegion(region string) ([]Instance, error) {
	client, err := m.getClient(region)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	var instances []Instance
	for _, reservation := range result.Reservations {
		for _, inst := range reservation.Instances {
			instance := m.parseInstance(inst, region)
			m.fetchProtectionInfo(client, &instance)
			instances = append(instances, instance)
		}
	}

	return instances, nil
}

func (m *EC2Manager) GetAllInstances() ([]Instance, error) {
	regions, err := m.GetAvailableRegions()
	if err != nil {
		return nil, err
	}

	var (
		instances []Instance
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	for _, region := range regions {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			
			insts, err := m.GetInstancesInRegion(r)
			if err != nil {
				return
			}

			mu.Lock()
			instances = append(instances, insts...)
			mu.Unlock()
		}(region)
	}

	wg.Wait()

	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Name == "" && instances[j].Name != "" {
			return false
		}
		if instances[i].Name != "" && instances[j].Name == "" {
			return true
		}
		if instances[i].Name != instances[j].Name {
			return instances[i].Name < instances[j].Name
		}
		return instances[i].ID < instances[j].ID
	})

	return instances, nil
}

func (m *EC2Manager) StartInstances(instanceIDs []string, region string) error {
	client, err := m.getClient(region)
	if err != nil {
		return err
	}

	_, err = client.StartInstances(context.TODO(), &ec2.StartInstancesInput{
		InstanceIds: instanceIDs,
	})
	return err
}

func (m *EC2Manager) StopInstances(instanceIDs []string, region string) error {
	client, err := m.getClient(region)
	if err != nil {
		return err
	}

	_, err = client.StopInstances(context.TODO(), &ec2.StopInstancesInput{
		InstanceIds: instanceIDs,
	})
	return err
}

func (m *EC2Manager) TerminateInstances(instanceIDs []string, region string) error {
	client, err := m.getClient(region)
	if err != nil {
		return err
	}

	_, err = client.TerminateInstances(context.TODO(), &ec2.TerminateInstancesInput{
		InstanceIds: instanceIDs,
	})
	return err
}

func (m *EC2Manager) SetTerminationProtection(instanceID, region string, enabled bool) error {
	client, err := m.getClient(region)
	if err != nil {
		return err
	}

	_, err = client.ModifyInstanceAttribute(context.TODO(), &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		DisableApiTermination: &types.AttributeBooleanValue{
			Value: aws.Bool(enabled),
		},
	})
	return err
}

func (m *EC2Manager) SetStopProtection(instanceID, region string, enabled bool) error {
	client, err := m.getClient(region)
	if err != nil {
		return err
	}

	_, err = client.ModifyInstanceAttribute(context.TODO(), &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		DisableApiStop: &types.AttributeBooleanValue{
			Value: aws.Bool(enabled),
		},
	})
	return err
}

func (m *EC2Manager) parseInstance(inst types.Instance, region string) Instance {
	name := ""
	for _, tag := range inst.Tags {
		if *tag.Key == "Name" {
			name = *tag.Value
			break
		}
	}

	return Instance{
		ID:           *inst.InstanceId,
		Name:         name,
		Status:       string(inst.State.Name),
		InstanceType: string(inst.InstanceType),
		Region:       region,
	}
}

func (m *EC2Manager) fetchProtectionInfo(client *ec2.Client, inst *Instance) {
	termResult, _ := client.DescribeInstanceAttribute(context.TODO(), &ec2.DescribeInstanceAttributeInput{
		InstanceId: aws.String(inst.ID),
		Attribute:  types.InstanceAttributeNameDisableApiTermination,
	})
	if termResult != nil && termResult.DisableApiTermination != nil {
		inst.TerminationProtection = *termResult.DisableApiTermination.Value
	}

	stopResult, _ := client.DescribeInstanceAttribute(context.TODO(), &ec2.DescribeInstanceAttributeInput{
		InstanceId: aws.String(inst.ID),
		Attribute:  types.InstanceAttributeNameDisableApiStop,
	})
	if stopResult != nil && stopResult.DisableApiStop != nil {
		inst.StopProtection = *stopResult.DisableApiStop.Value
	}
}

func GetRegionDisplayName(region string) string {
	if name, ok := RegionNames[region]; ok {
		return fmt.Sprintf("%s (%s)", region, name)
	}
	return region
}
