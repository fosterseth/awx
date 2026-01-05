# Django-Ansible-Base SSH Key Requirement

This document addresses the issue where django-ansible-base is unable to be fetched from a private GitHub repository when running make docker-compose-build and helps improve the django-ansible-base pip requirement. 

**Note:** This document was created with AI-generated assistance from Claude. 

## The Issue

The `django-ansible-base` dependency is specified in `requirements/requirements_git.txt:4` using SSH authentication:

```
django-ansible-base @ git+ssh://git@github.com/ansible-automation-platform/django-ansible-base@stable-2.6#egg=django-ansible-base[rest-filters,jwt_consumer,resource-registry,rbac,feature-flags]
```

This requires an SSH key authorized for the `ansible-automation-platform/django-ansible-base` private repository.

## How the Build Works

Looking at `Dockerfile.dev:75` and `Makefile:627-633`, the build process:

1. Uses Docker BuildKit's SSH mount feature: `RUN --mount=type=ssh cd /tmp && make requirements_awx`
2. Passes your SSH agent socket: `--ssh default=$(SSH_AUTH_SOCK)`
3. Sets up GitHub in known_hosts: `Dockerfile.dev:61-62`

## Solutions

### For Local Development

You need to ensure your SSH agent has a valid key loaded before running `make docker-compose-build`:

```bash
# 1. Start SSH agent (if not already running)
eval "$(ssh-agent -s)"

# 2. Add your authorized SSH key
ssh-add ~/.ssh/id_rsa  # or whatever key has access to the repo

# 3. Verify SSH_AUTH_SOCK is set
echo $SSH_AUTH_SOCK

# 4. Test GitHub authentication
ssh -T git@github.com

# 5. Now build
make docker-compose-build
```

## Common Issues & Fixes

### Issue: SSH_AUTH_SOCK not set

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc)
if [ -z "$SSH_AUTH_SOCK" ]; then
  eval "$(ssh-agent -s)"
fi
```

### Issue: Key not authorized for the repository

- Ensure your SSH key is added to your GitHub account
- Verify you have access to `ansible-automation-platform/django-ansible-base`
- Contact your team to get repository access

### Issue: Docker BuildKit not enabled

```bash
export DOCKER_BUILDKIT=1
```

## Alternative: Use Editable Dependencies

If you have `django-ansible-base` checked out locally, you can use editable dependencies to bypass the SSH requirement:

```bash
# From the AWX root directory
cd tools/docker-compose/editable_dependencies
ln -s /path/to/your/django-ansible-base ./

# Then build with editable dependencies enabled
EDITABLE_DEPENDENCIES=true make docker-compose-build
```

See `tools/docker-compose/editable_dependencies/README.md` for more details.

## For CI/CD

The GitHub Actions workflows (`.github/actions/awx_devel_image/action.yml:29-47`) handle this by:
- Using the `AWX_PRIVATE_REPO_KEY` secret if available
- Or generating a placeholder key (which will fail for private repos)

## Relevant Files

- `requirements/requirements_git.txt:4` - Django-ansible-base dependency declaration
- `Makefile:627-633` - Docker compose build target with SSH mount
- `Dockerfile.dev:61-62` - GitHub known_hosts setup
- `Dockerfile.dev:75` - Requirements installation with SSH mount
- `tools/docker-compose/editable_dependencies/README.md` - Editable dependencies documentation
- `.github/actions/awx_devel_image/action.yml` - CI/CD SSH key handling

## Quick Troubleshooting Checklist

- [ ] SSH agent is running (`ps aux | grep ssh-agent`)
- [ ] SSH_AUTH_SOCK environment variable is set (`echo $SSH_AUTH_SOCK`)
- [ ] SSH key is loaded in agent (`ssh-add -l`)
- [ ] SSH key is authorized on GitHub account
- [ ] You have access to the `ansible-automation-platform/django-ansible-base` repository
- [ ] Can authenticate to GitHub via SSH (`ssh -T git@github.com`)
- [ ] Docker BuildKit is enabled (`DOCKER_BUILDKIT=1`)

# Improving the django-ansible-base Pip Requirement

## Current Issues

The dependency in `requirements/requirements_git.txt:4` uses SSH authentication to a private repository:
```
django-ansible-base @ git+ssh://git@github.com/ansible-automation-platform/django-ansible-base@stable-2.6#egg=django-ansible-base[rest-filters,jwt_consumer,resource-registry,rbac,feature-flags]
```

This creates friction because:
- Requires SSH key setup for all developers
- Complicates CI/CD secret management
- Fails silently if SSH isn't configured properly

## Recommended Improvements

### 1. **Switch to HTTPS with token authentication** (Most practical)

```python
django-ansible-base @ git+https://${GITHUB_TOKEN}@github.com/ansible-automation-platform/django-ansible-base@stable-2.6#egg=django-ansible-base[rest-filters,jwt_consumer,resource-registry,rbac,feature-flags]
```

**Benefits:**
- Works with GitHub personal access tokens or PAT
- Easier for CI/CD (already using secrets)
- Doesn't require SSH agent setup

### 2. **Use version tags instead of branch references**

```python
django-ansible-base @ git+ssh://git@github.com/ansible-automation-platform/django-ansible-base@v2.6.5#egg=django-ansible-base[...]
```

**Benefits:**
- More reproducible builds (branches can move)
- Easier to track what version is actually installed
- Aligns with your workflow in `.github/workflows/dab-release.yml` which tracks releases

### 3. **Consider switching to the public repository**

Your workflow already references `ansible/django-ansible-base` for releases. If the private `ansible-automation-platform` repo doesn't have unique patches, consider using:
```python
django-ansible-base @ git+https://github.com/ansible/django-ansible-base@2.6.5#egg=django-ansible-base[...]
```

### 4. **Publish to a private PyPI server**

If you have enterprise infrastructure:
```python
django-ansible-base[rest-filters,jwt_consumer,resource-registry,rbac,feature-flags]==2.6.5
```

With `pip.conf`:
```ini
[global]
extra-index-url = https://pypi.your-company.com
```

### 5. **Improve the existing tooling**

Update `requirements/django-ansible-base-pinned-version.sh` to:
- Support both SSH and HTTPS modes
- Validate authentication before attempting install
- Provide better error messages

## Recommendation

Start with **option #1 (HTTPS with tokens)** as it's the least disruptive change while solving the main authentication friction.
