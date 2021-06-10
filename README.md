# AWS IoT device provisioning by trusted user
This Bootcamp will provide an understanding of the basics to configure and run [device provisioning by trusted user](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html#trusted-user) using AWS IoT Device Client. 

During this workshop you will learn how to connect devices to AWS IoT, install Device Client software and initiate provisioning workflow.

The guideline was written to be used on an Ubuntu Amazon EC2 Instance. But it should be easy to replace the code to be used with your own device (ex. RaspberyPI), or other operating system. Most of this workshop is independant of the device type or processor architecture.

To complete this workshop you will need an active AWS account, and basic understanding of [AWS IoT](https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html).

## Intro
AWS provides several different ways to provision a device and install unique client certificates on it. AWS also offer [an interactive tool to help guide your decision](https://pythia.architecture.aws.dev/conversation/WoJ6Vp/WoJ6Vp-4pKLxC/DECISION_1597211738237). These options are described in detail in the white paper titled, [Device Manufacturing and Provisioning with X.509 Certificates in AWS IoT Core](https://d1.awsstatic.com/whitepapers/device-manufacturing-provisioning.pdf).

This workshop focus on the option of 'Fleet Provisioning by Trusted User'. Fleet Provisioning by Trusted User is the recommended approach when a high degree of security is needed, when the manufacturing chain is not trusted, or it is not possible to provision devices in the manufacturing chain due to technical limitations, cost, or application specific limitations. Using this approach, the credentials are never exposed to the manufacturing supply chain. Read [here](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html) for more details.

### Basic flow
Human installer uses a mobile/web application, he write and own, and authenticates with AWS. Using the trusted (authenticated) user APIs, the installer receives a temporary X.509 certificate and private key that is valid for five minutes. Using the mobile/web application, the credentials are delivered to the device. The device connects to AWS IoT and exchanges the temporary credentials for a unique X.509 certificate signed with the AWS CA and a private key. During this workflow, the AWS resources including Thing name, Policy, and Certificate are set up in the AWS Account.

![fp_by_trasted_user_flow.png](https://github.com/doronbl/aws-iot-fleet-provisioning-trusted-user-workshop/blob/main/images/fp_by_trasted_user_flow.png?raw=true)

## Setting up cloud resources
This workshop assumes the use of US East (N. Virginia) us-east-1 region.
For the sake of simplicity we will use the default VPC.
We will provision the following resources:
1. Cloud9 IDE which will act as our development platform
2. Key pair to access our EC2 instance on the next step
3. EC2 Ubuntu instance for emulating IoT device
5. AWS IoT resources such as IoT Policys,Fleet Provisioning template, Thing, certificate, etc
6. Lambda function to validate parameters passed from the device before allowing the device to be provisioned (Pre-provisioning hook)
7. Related IAM roles

### AWS IoT Core Resources
On the AWS console navigate to the IoT Core service. Make sure you are using US East (N. Virginia) us-east-1 region.
For a later step we will need the AWS IoT [Device data endpoint](https://docs.aws.amazon.com/iot/latest/developerguide/iot-connect-devices.html?icmpid=docs_iot_hp_settings#iot-connect-device-endpoints).

On the AWS IoT Core service console, on the left pannel at the bottom click 'Settings' and copy the device data endpoint.

#### AWS IoT Policy
[IoT policies](https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html) consists of operations that allow device to connect to the AWS IoT Core message broker, send and receive MQTT messages, and get or update a device's shadow.
Policies are attached to a certificate which define the device identity. When device connectes, AWS IoT uses the certificate to find the attached policy and the authorization rules it holds.

Fleet provisioning workflow requires two IoT Policies:
1. First IoT policy is attached by AWS IoT to the temporary certificate, so the device can initiate the provisioning workflow. 
2. Second policy is attached to the permanent certificate provisioned into the device.

Lets create the first IoT policy to be attached to the temporary certificates:

1. On the IoT Core service console navigate to 'Secure' and then 'Policies'.
2. Click 'Create a policy'
3. Set Name: 'TrustedUserProvisioningPolicy'
4. Click 'Advanced mode' under the 'Add statements' section, and replace the policy content with the below. You will have to replace 'account' with your account id.
5. When done, click on 'Create'

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

Next, we need to create second IoT Policy which will be attached to the permanent certificate provisioned into the device. This policy is referenced by the provisioning template and attached to the permanent certificate during the workflow process.
Below policy allow the device to connect, publish, and subscribe to MQTT messages on topics prefixed by the Thing name (MQTT client ID & and registered Thing name in AWS IoT Core).

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
4. Click 'Enable template' at the bottom of the page
5. Navigate to 'Fleet provisioning templates', select created template and click 'Edit JSON'
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
Make sure you are using US East (N. Virginia) us-east-1 region in the console.

#### Create a New Cloud9 IDE Instance
We will use Cloud9 IDE environment to emulate our trusted user API calls.

From the AWS Console, navigate to Cloud9, select US East (N. Virginia) us-east-1, then create a new environment with the following environment settings:

1. Name: fp_workshop
2. Click 'Next step'
3. Leave defaults and click 'Next step'
4. Review environment details and click 'Create environment'

#### Key pair
Create key pair to be used by later SSH sessions.
1. Navigate to the AWS EC2 service console. Under 'Network & Security' select 'Key Pairs', and click 'Create key Pairs'.
    * Name: fp_workshop_kp
    * File format: _select file format matching your SSH client_
    * Click: Create key pair

#### Create Ubuntu instance for emulating IoT Device
We will Use Ubuntu EC2 with ARM architecture to emulate our IoT device.

Navigate to the AWS EC2 console. Under 'Instances' select 'Instances', and click 'Launch instance'.

1. Choose an Amazon Machine Image (AMI)
    * Ubuntu Server 18.04 LTS
    * Make sure to select select the **64-bit (Arm)** option
    * Click: 'Select'
2. Choose an Instance Type
    * t4g.micro (Free Trial available)
    * Click: 'Next: Configure Instance Details'
3. Configure Instance Details
    * Leave defaults
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
     * 'Choose an existing key pair'
     * make sure 'fp_workshop_kp' is selected
     * acknowledge you have the key pair
     * Click: 'Launch Instances'

Wait until the instance 'Status check' becomes green (passed) & Note down the instance public IP.

## Setting up the device
AWS have multiple options for device developers, these options include [IoT SDK](https://docs.aws.amazon.com/iot/latest/developerguide/iot-sdks.html)
for multiple programming languages. In addition to the IoT SDKs you can choose to use [IoT Device Client](https://github.com/awslabs/aws-iot-device-client#introduction);
a free, open-source, modular software written in C++ that you can compile and install on your Embedded Linux based IoT devices to access AWS IoT Core, AWS IoT Device Management, and AWS IoT Device Defender features by default.
Using IoT Device Client we greatly simplify our development, so will use it for our example device.

SSH into the Ubuntu instance public IP using your private key and user 'ubuntu'.

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
Using a trusted user, such as an end user or an installer with a known account, can simplify the device manufacturing process. Instead of a unique client certificate, devices have a temporary certificate that enables the device to connect to AWS IoT for only 5 minutes. During that 5-minute window, the trusted user obtains a unique client certificate with a longer life and installs it on the device. The limited life of the claim certificate minimizes the risk of a compromised certificate. 
For more information, see [Provisioning by trusted user](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html#trusted-user).

To keep things simple, we will not use web or mobile app, instead we will use our Cloud9 environment into which you need to authenticate and authorise in order to call the API for creating temporary claim certificate.

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
### Create temporary provisioning claim
To create temporary provisioning claim run the following AWS CLI command:
```bash
aws iot create-provisioning-claim --template-name TrustedUserProvisioningTemplate
```
See [here](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iot/create-provisioning-claim.html) for more information about above AWS CLI command.

**Note**: This claim is valid for only 5 minutes.

Copy the result PrivateKey and the certificatePem attributes to into below files on the device:
```bash
# PrivateKey
$HOME/cert/device-client-fp.pem.crt
# certificatePem
$HOME/cert/device-client-fp.private.pem.key
```

You will have to transform the formatting of the text within the files.
Run below bash commands to reformat the files and set appropriate file permissions.
```bash
sed -i 's/\\n/\n/g' $HOME/cert/device-client-fp.pem.crt
sed -i 's/\\n/\n/g' $HOME/cert/device-client-fp.private.pem.key
chmod 644 $HOME/cert/device-client-fp.pem.crt
chmod 600 $HOME/cert/device-client-fp.private.pem.key
```
### Initiate Fleet Provisioning from the device
On the device run below set of commands.

*Note*: It is best practice to use the AWS IoT Thing Name as the MQTT client ID for connecting as a device over MQTT.
```bash
export ENDPOINT=<Device data endpoint>
cd $HOME/aws-iot-device-client/build
./aws-iot-device-client --enable-fleet-provisioning true \
                        --endpoint "$ENDPOINT" \
                        --cert $HOME/cert/device-client-fp.pem.crt \
                        --key $HOME/cert/device-client-fp.private.pem.key \
                        --root-ca $HOME/cert/AmazonRootCA1.pem \
                        --thing-name device-client-fp \
                        --fleet-provisioning-template-name TrustedUserProvisioningTemplate \
                        --enable-jobs false \
                        --enable-tunneling false \
                        --enable-device-defender false \
                        --fleet-provisioning-template-parameters "{\"ThingName\": \"device-client-fp\"}"
```
When done, you should be able to see permanent certificate and your Thing registered in AWS IoT Core console. Validate that your certificate is attached to the pubsub policy.

## Useful Resources
[Device provisioning developer guide](https://docs.aws.amazon.com/iot/latest/developerguide/iot-provision.html)
[Device Manufacturing and Provisioning with X.509 Certificates in AWS IoT Core whitepaper](https://d1.awsstatic.com/whitepapers/device-manufacturing-provisioning.pdf)
