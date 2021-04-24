# AWS IoT Fleet Provisioning by trusted user
A WORK IN PROGRESS

This workshop demonstrate how to use AWS IoT Core Fleet Provisioning with trusted user to automate device provisioning workflow. 

To complete this workshop you will need an active AWS account.

This workshop will use AWS EC2 Ubuntu instance to emulate a device. If you are using different operating system you will have to modify the operating system setup steps to your OS. Most of this workshop is independant of the device type.

## Setting up cloud resources
This workshop assumes the usage of US East (N. Virginia) us-east-1 region.
For the sake of simplicity we will use your region default VPC.

### AWS IoT Core Resources
On the AWS console navigate to the IoT Core service. Make sure you are using US East (N. Virginia) us-east-1 region.

#### AWS IoT Policy
[IoT policies](https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html) define the operations a device can perform in AWS IoT. IoT policies are attached to device certificates. When a device presents the certificate to AWS IoT, it is granted the permissions specified in the policy.

First we need to create AWS IoT policy which will be used by our device during the provisioning workflow.

On the AWS IoT console navigate to 'Secure' and then 'Policies'.
Click 'Create a policy'
Name: 'TrustedUserProvisioningPolicy'
Click 'Advanced mode' and replace the policy content with the below. You will have to replace 'account' with your account id. When done, click 'Create'
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:Publish"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:account:topic/$aws/certificates/create/json",
        "arn:aws:iot:us-east-1:account:topic/$aws/provisioning-templates/TrustedUserProvisioningTemplate/provision/json"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:Receive",
        "iot:Subscribe"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:account:topic/$aws/certificates/create/json/accepted",
        "arn:aws:iot:us-east-1:account:topic/$aws/certificates/create/json/rejected",
        "arn:aws:iot:us-east-1:account:topic/$aws/provisioning-templates/TrustedUserProvisioningTemplate/provision/json/accepted",
        "arn:aws:iot:us-east-1:account:topic/$aws/provisioning-templates/TrustedUserProvisioningTemplate/provision/json/rejected"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:us-east-1:account:client/${iot:Connection.Thing.ThingName}"
    }
  ]
}
```

We need to create second IoT Policy which the device will use once its permanent certificate will be in place. This policy will be referenced by the provisioning template.
This policy will allow the device to publish and subscribe to MQTT messages on topic name equal to the device id.
Create new IoT policy, name it 'pubsub', and set below content for the policy
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:Publish",
        "iot:Receive"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:account:topic/${iot:Connection.Thing.ThingName}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:Subscribe"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:account:topicfilter/$aws/things/${iot:Connection.Thing.ThingName}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iot:Connect"
      ],
      "Resource": [
        "arn:aws:iot:us-east-1:account:client/${iot:Connection.Thing.ThingName}"
      ]
    }
  ]
}
```
#### AWS IoT Fleet Provisioning template
A [provisioning template](https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html) is a JSON document that uses parameters to describe the resources your device must use to interact with AWS IoT.
When configuring Fleet Provisioning template you have an option to configure [Pre Provisioning Hook](https://docs.aws.amazon.com/iot/latest/developerguide/pre-provisioning-hook.html).
Pre Provisioning Hook is a Lambda function to validate parameters passed from the device before allowing the device to be provisioned.
For the sake of simplicity we will not use Pre Provisioning Hook.

On the AWS IoT console navigate to 'Onboard', 'Fleet provisioning templates'.
```
Click 'Create template'
Click 'Get started'
Template name: TrustedUserProvisioningTemplate 
Under 'Provisioning role' click 'Create Role' and name it 'IoTFleetProvisioningRole'
Click 'Next'
Choose 'Use an existing AWS IoT policy' and select 'TrustedUserProvisioningPolicy' created earlier
Click 'Create template'
Click 'Enable template'
Navigate to the created template and click 'Edit JSON'
Replace the content of the template with below content, and click 'Save as new version'
{
    "Parameters" : {
        "ThingName" : {"Type" : "String" }
    },
    "Resources" : {
        "thing" : {
            "Type" : "AWS::IoT::Thing",
            "Properties" : {
                "ThingName" : {"Ref" : "ThingName"}
            }
        },  
        "certificate" : {
            "Type" : "AWS::IoT::Certificate",
            "Properties" : {
                "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                "Status" : "ACTIVE"      
            }
        },
        "policy" : {
            "Type" : "AWS::IoT::Policy",
            "Properties" : {
                "PolicyName": "pubsub"
            }
        }
    }
}
```

### EC2 resources

#### Key pair
Navigate to the AWS EC2 console. Under 'Network & Security' select 'Key Pairs', and click 'Key Pairs'.
    
    Name: <any name>
    File format: ppk
    Click: Create key pair
    
#### IoT Device Emulator
We will Use Ubuntu EC2 with ARM architecture to emulate our IoT device.

Navigate to the AWS EC2 console. Under 'Instances' select 'Instances', and click 'Launch instance'.

    Step 1: Choose an Amazon Machine Image (AMI)
        Ubuntu Server 18.04 LTS & select 64-bit (Arm)
        Click: 'Select'
    Step 2: Choose an Instance Type
        t4g.micro (Free Trial available)
        Click: 'Next: Configure Instance Details'
    Step 3: Configure Instance Details
        Leave defaults or select VPC & subnets
        Click: 'Next: Add Storage'
    Step 4: Add Storage
        Click: 'Next: Add Tags'
    Step 5: Add Tags
        Click: 'Next: Configure Security Group'
    Step 6: Configure Security Group
        'Create a new security group'
        'Security group name': ssh
        Click: 'Review and Launch'
    Step 7: Review Instance Launch
        Click: 'Launch'
        'Choose an existing key pair'  Or 'Create new key pair'
        acknowledge you have the key pair
        Click: 'Launch Instances'
    Wait until the instance state becomes 'Running'
    Note down the instance public IP
#### Create Cloud9 IDE environment
We will use Cloud9 IDE environment to emulate our trusted user API calls.

## Setting up the device
SSH into the instance using your private key and user 'ubuntu'
```
sudo apt update
sudo apt -y upgrade
sudo reboot
SSH into the instance using your private key and user 'ubuntu'
# Install pre-requisits for the Device Client
sudo apt install -y cmake g++ libssl-dev
git clone https://github.com/awslabs/aws-iot-device-client.git
cd aws-iot-device-client
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/aarch64-linux-gnu/libcrypto.so.1.1 ../
cmake --build . --target aws-iot-device-client
# You can build and run Device Client unit tests to verify all pass before you continue (Optional)
cmake --build . --target test-aws-iot-device-client
./test/test-aws-iot-device-client
# Download Amazon Root CA for MQTT mutual authentication with IoT Core
mkdir $HOME/cert
chmod 700 $HOME/cert
cd $HOME/cert
wget https://www.amazontrust.com/repository/AmazonRootCA1.pem
chmod 644 ./AmazonRootCA1.pem
```
