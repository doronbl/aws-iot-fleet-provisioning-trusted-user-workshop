# AWS IoT Fleet Provisioning by trusted user
A WORK IN PROGRESS

This workshop demonstrate how to use AWS IoT Core Fleet Provisioning with trusted user to automate device provisioning workflow. 

To complete this workshop you will need an active AWS account.

This workshop will use AWS EC2 Ubuntu instance to emulate a device. If you are using different operating system you will have to modify the operating system setup steps to your OS. Most of this workshop is independant of the device type.

## Setting up cloud resources
This workshop assumes the usage of US East (N. Virginia) us-east-1 region.
For the sake of simplicity we will use the default VPC.

### AWS IoT Core Resources
On the AWS console navigate to the IoT Core service. Make sure you are using US East (N. Virginia) us-east-1 region.

#### AWS IoT Policy
[IoT policies](https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html) define the operations a device can perform in AWS IoT. IoT policies are attached to device certificates. When a device presents the certificate to AWS IoT, it is granted the permissions specified in the policy.

First we need to create AWS IoT policy which will be used by our device during the provisioning workflow.

1. On the AWS IoT console navigate to 'Secure' and then 'Policies'.
2. Click 'Create a policy'
3. Set Name: 'TrustedUserProvisioningPolicy'
4. Click 'Advanced mode' and replace the policy content with the below. You will have to replace 'account' with your account id. When done, click 'Create'

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

Next, we need to create second IoT Policy which the device will use once its permanent certificate will be in place. This policy will be referenced by the provisioning template so it will be attached to the permanent certificate.
Below policy allow the device to publish and subscribe to MQTT messages on topics prefixed by the Thing name. Use the AWS IoT Thing Name as the MQTT client ID for connecting as a device over MQTT.
Create new IoT policy, name it 'pubsub', and set below content for the policy. You will have to replace 'account' with your account id.
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

1. On the AWS IoT console navigate to 'Onboard', 'Fleet provisioning templates'.
2. Click 'Create template'
3. Click 'Get started'
    * Template name: TrustedUserProvisioningTemplate 
    * Under 'Provisioning role' click 'Create Role' and name it 'IoTFleetProvisioningRole'
    * Click 'Next'
    * Choose 'Use an existing AWS IoT policy' and select 'TrustedUserProvisioningPolicy' created earlier
    * Click 'Create template'
4. Click 'Enable template'
5. Navigate to the created template and click 'Edit JSON'
6. Replace the content of the template with below content, and click 'Save as new version'
```
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
1. Navigate to the AWS EC2 console. Under 'Network & Security' select 'Key Pairs', and click 'Key Pairs'.
    * Name: <any name>
    * File format: ppk
    * Click: Create key pair
    
#### Create Ubuntu instance for emulating IoT Device
We will Use Ubuntu EC2 with ARM architecture to emulate our IoT device.

Navigate to the AWS EC2 console. Under 'Instances' select 'Instances', and click 'Launch instance'.

1. Choose an Amazon Machine Image (AMI)
    * Ubuntu Server 18.04 LTS & select 64-bit (Arm)
    * Click: 'Select'
2. Choose an Instance Type
    * t4g.micro (Free Trial available)
    * Click: 'Next: Configure Instance Details'
3. Configure Instance Details
    * Leave defaults or select VPC & subnets
    * Click: 'Next: Add Storage'
4. Add Storage
    * Click: 'Next: Add Tags'
5. Add Tags
    * Click: 'Next: Configure Security Group'
6. Configure Security Group
     * 'Create a new security group'
     * 'Security group name': ssh
     * Click: 'Review and Launch'
7. Review Instance Launch
     * Click: 'Launch'
     * 'Choose an existing key pair'  Or 'Create new key pair'
     * acknowledge you have the key pair
     * Click: 'Launch Instances'

Wait until the instance state becomes 'Running' & Note down the instance public IP.
#### Create a New Cloud9 IDE Instance
We will use Cloud9 IDE environment to emulate our trusted user API calls.

From the AWS Console, navigate to Cloud9, select the region you will be working in for all the labs, then create a new environment with the following environment settings:

* Create a new instance for environment (EC2)
* t3.small (2 GiB RAM + 2 vCPU)
* Amazon Linux
* Cost-savings setting: After four hours
* Network settings: Default VPC and public subnet

## Setting up the device
SSH into the instance public IP using your private key and user 'ubuntu'.

If you are using different operating system than Ubuntu you will have to modify some of below shell commands to match your OS.
```
sudo apt update
sudo apt -y upgrade
# Install pre-requisits for the Device Client
sudo apt install -y cmake g++ libssl-dev git
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
## Obtain a temporary provisioning claim certificate
If you cannot securely install unique client certificates on your IoT device before they are delivered to the end user, but the end user or an installer can use an app to register the devices and install the unique device certificates, you want to use the provisioning by trusted user process.

Using a trusted user, such as an end user or an installer with a known account, can simplify the device manufacturing process. Instead of a unique client certificate, devices have a temporary certificate that enables the device to connect to AWS IoT for only 5 minutes. During that 5-minute window, the trusted user obtains a unique client certificate with a longer life and installs it on the device. The limited life of the claim certificate minimizes the risk of a compromised certificate. 
For more information, see [Provisioning by trusted user](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html#trusted-user).

To keep things simple, we will not use web or mobile app, instead we will use our Cloud9 environment into which you need to authenticate and authorise in order to call the API for creating temporary claim certificate.
 See [here](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iot/create-provisioning-claim.html) for more information about AWS CLI command we will use.

Make sure the principle you are using within Cloud9 environment have the following IAM policy attached.
This IAM policy allow the principle to call the IoT CreateProvisioningClaim API for TrustedUserProvisioningTemplate template.
You will have to replace 'account' with your account id.
```
{
    "Effect": "Allow",
    "Action": [
        "iot:CreateProvisioningClaim",
    ],
    "Resource": [
        "arn:aws:us-east-1:account:provisioningtemplate/TrustedUserProvisioningTemplate"
    ]
}
```

You will have to copy the PrivateKey and the certificatePem attributes 