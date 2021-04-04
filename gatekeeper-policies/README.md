# Example Gatekeeper policies and constraints

We're going to deploy policies as well as contraints to implement more sensible security defaults for our cluster via OPA Gatekeeper.

This draws from the official [Gatekeeper Library](https://github.com/open-policy-agent/gatekeeper-library) as well as Kubernetes' [Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/).

## How to deploy?
This was intended to either be deployed by Flux against the `gatekeeper-policies` folder or via a `kubectl apply --recursive -f gatekeeper-policies`.

## How to test it works?
There is an example that will be blocked by each policy check in the `gatekeeper-tests` folder once the policies and constraints have been installed.

## What policies are we enforcing by default in our Quickstart?

I started by emulating the example [Restricted](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) PSP with Gatekeeper as our default and then added a few more thing that were not covered by PSPs but that we can with Gatekeeper. We excluded the `kube-system` namespace as many of our cluster's infrastrucutre add-ons we're deploying there require exceptions to these restrictions.

I then also had a look at OpenShift's [default restricted Security Context Constraints](https://docs.openshift.com/container-platform/4.7/authentication/managing-security-context-constraints.html#security-context-constraints-about_configuring-internal-oauth) which itself seems to mostly mirror the Kubernetes default restricted PSP example linked above. So, this appears to be a comparable level of constraints to that minus their default of an SELinux configured on the Nodes and the associated requirement to for a Pod to use pre-allocated MCS labels.

**NOTE:** that this is an example and there may be valid reasons why particular workloads need exceptions to these rules - particularly if they are infrastrucutre or security add-ons to the cluster. It is possible with Gatekeeper constraints to exclude additional namespaces or, really, any label selector from these rules as appropriate.

You are welcome to edit the constraints as required in your fork of this repo - including adding any additional ones you may need as well.

### Block running privileged containers

Privileged mode comes from Docker where it "enables access to all devices on the host as well as set some configuration in AppArmor or SELinux to allow the container nearly all the same access to the host as processes running outside containers on the host." (https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).

One of the main reasons why people generally want privileged mode is that it allows things running within a container on the host to call the local container runtime/socket and launch more containers. This is an anti-pattern with Kubernetes - which should be launching all the Pods/containers on all of its hosts.

There is a more granular way to allow access to specific privileges/capabilities using the capabilities policy. We block both privleged mode as well as all the capabilities by default excluding `kube-system`.

### Block the ability for the Pods to request any Linux capabilities (e.g NET_ADMIN)

In addition to privleged mode which exposes a number of capabilities at once there is also a way to granularly controled which capabilities.

You can get a list of those capabilities [here](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).

We block access to all of the capabilities excluding `kube-system` by  default.

### Block the ability for Pods to run as the root user

By default if the creator of the image doesn't specify a USER in the Dockerfile and/or you don't specify one at runtime then the container will run as `root` (https://docs.docker.com/engine/reference/run/#user).  It does this within its own namespace and the constraints of the container environment and the Gatekeeper policies - but it is still a bad idea for it to run as root unnecessarily. Running it as a non-root user makes it just all that much harder for somebody to escalate to root on the host should there be a bug or vulnerability in the system.

We do not allow the user ID (UID) or group ID (GID) of 0 - which are the root UID and GID in Linux - by default (excluding `kube-system`).

### Block the ability for Pods to use the host's namespace(s)

One of the key security features of Kubernetes is puts each Pod into its own seperate linux [namespace](https://en.wikipedia.org/wiki/Linux_namespaces). This means that it can't see the processes, volume mounts or network interfaces etc. of either the other Pods or the host. 

Is is possible, though, to ask in the PodSpec to be put into the host's namespace and therefore to see everything.

We are blocking the ability to do that by default excluding `kube-system`.

### Block the ability to use the host's network

By default with EKS each Pod gets its own VPC IP and that is the network interface that it communicates with the network through.

It is possible to ask in the PodSpec to be exposed through the host's network interface instead. 

We are blocking the ability to do that by default excluding `kube-system`.

### Block the ability for a Pod to mount certain types of volumes (e.g. host volumes)

A Pod can request to mount **any** path on the host/Node/Instance that it is running on (e.g. /etc, /proc, etc.).

We're blocking the abilty to do that by default excluding those things running in `kube-system`.

### Require any Pods to declare CPU & memory limits

Kubernetes has the concepts of `requests` and `limits` when it comes to CPU & Memory. With requests it is telling Kubernetes how much CPU and Memory a Pod is *guaranteed* to get - its minimum. It can use more than that though. While limits, on the other hand, see Kubernetes enforce at that threshold and, in the case of memory, will terminate the container(s) if they exceed the limit.

By default we're running a tight ship and are not only requiring that each of the containers in our Pods have **BOTH** a CPU & Memory request & limit - and that they are the same thing. And, we're excluding `kube-system` from this though.

This is the ideal configuration if you are running a multi-tenant cluster to ensure that there are not any 'noisy neighbor' issues where people who don't specify limits end up using the entire Node. It forces each service to think about how much CPU and Memory they actually need and declare it in their Spec templates when they deploy to the cluster.

### Require any Pods to declare readiness and liveness probes/healthchcecks

Kubernetes also has the concept of probes which are often also referred to as health checks.

The readiness probe controls whether the service should be sent traffic

The liveness probe controls whether the pod should be healed through replacement

We're requiring that you specify both probes in your PodSpec - excluding in `kube-system`.

### Blocking the use of the `latest` tag

Almost by definition the `latest` tag will change as new versions are released - often before you've tested and deployed the new version explicity to your cluster. This can lead to things like a Pod is healed or scaled and that leads to the new Pods running the new version alongside the old version without you knowing.

It is best practice to always specify a specific version/tag when deploying to your clusters so any upgrades/changes are declared and intentional.

Excluding `kube-system` by default.

## What is an example PodSpec that passes with all the default policies?

There is an example in `gatekeeper-tests/allowed.yaml` as follows. If you find that something isn't working add the relevent section from this example.

**NOTE:** The user and group need to be created within the container and the app needs relevant permissions in order to run as that user and group you specify. In the case of our nginx example they created a 2nd image and [Dockerfile](https://github.com/nginxinc/docker-nginx-unprivileged/blob/main/Dockerfile-debian.template) to do this and had to give up some things like being able to do HTTP on port 80 with the container running as a non-root user. The 101 we are specifying for the UID and GID we got from the Dockerfile and it will vary from container to container - we just need it to not be root's UID/GID of 0.

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-allowed
  labels:
    app: nginx-allowed
spec:
  securityContext:
    supplementalGroups:
      - 101
    fsGroup: 101
  containers:
    - name: nginx
      image: nginxinc/nginx-unprivileged:1.19
      resources:
        limits:
          cpu: 1
          memory: 1Gi
        requests:
          cpu: 1
          memory: 1Gi
      ports:
      - containerPort: 8080
        protocol: TCP
      securityContext:
        runAsUser: 101
        runAsGroup: 101
        capabilities:
          drop:
            - ALL
      readinessProbe:
          httpGet:
            scheme: HTTP
            path: /index.html
            port: 8080
      livenessProbe:
          httpGet:
            scheme: HTTP
            path: /index.html
            port: 8080
```

## What are some other policies you might want to consider?

### Limiting what repositories containers can be pulled from

You might want to limit which repositories containers can be pulled from to, for example, your private AWS Elastic Container Registries. If you also have a process there to vet them then this can enforce that policy is followed.

There is an example of how to do this at https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/general/allowedrepos 

Since you'll need to know what repositories are relevant for your organisation, and perhaps clone some add-ons from public repos to those, this is a policy and constraint you'll need to add to Gatekeeper yourself.

### Requiring certain labels (e.g. to help determine who 'owns' an app on the cluster and/or who to call when it breaks)

Often having the information right in the cluster and on the objects as to who owns them and who to call when it breaks can be useful to minimise the duration of an outage. It might also prove helpful in cost attribution and other Enterprise concerns.

There is an example of how to do this at https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/general/requiredlabels

Since you'll know the kinds of labels you'll need for your organisation this is a policy and constraint you'll need to add to Gatekeeper yourself.