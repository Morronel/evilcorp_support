# -*- coding: utf-8 -*-
"""
Seed the EvilCorp CTF database with:
- default 'support' and 'admin' users
- thousands of tickets with only 3 critical (one contains admin creds)
- an initial welcome message to guide students
"""
import os, random, datetime as dt, uuid
from app import db, User, Ticket, Message, app

RANDOM_SEED = int(os.environ.get("EVILCORP_SEED", "1337"))
random.seed(RANDOM_SEED)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "SynthAdm1n!2025")
SUPPORT_PASSWORD = os.environ.get("SUPPORT_PASSWORD", "SupportR0xx!")
TOTAL_TICKETS = int(os.environ.get("TOTAL_TICKETS", "3000"))
CRITICAL_COUNT = 3  # exactly 3

LOREM = [
    "lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
    "adipiscing", "elit", "sed", "do", "eiusmod", "tempor",
    "incididunt", "ut", "labore", "et", "dolore", "magna", "aliqua",
    "ut", "enim", "ad", "minim", "veniam", "quis", "nostrud", "exercitation",
    "ullamco", "laboris", "nisi", "ut", "aliquip", "ex", "ea", "commodo", "consequat",
    "duis", "aute", "irure", "dolor", "in", "reprehenderit", "in", "voluptate", "velit",
    "esse", "cillum", "dolore", "eu", "fugiat", "nulla", "pariatur",
    "excepteur", "sint", "occaecat", "cupidatat", "non", "proident"
]

def ipsum(n):
    return " ".join(random.choice(LOREM) for _ in range(n)).capitalize() + "."

def make_title():
    prefixes = [
        "Portal", "Node", "Quantum", "Neon", "Synth", "Plasma", "Vector", "Matrix",
        "Daemon", "Circuit", "Kernel", "Fiber", "Relay", "Gateway", "Emitter"
    ]
    nouns = ["glitch", "warning", "timeout", "sync error", "latency spike", "auth hiccup",
             "shader bug", "UI blur", "cache miss", "TLS wobble", "NIC hiccup", "db lock"]
    return f"{random.choice(prefixes)} {random.choice(nouns)}"

def main():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Users
        support = User(username="support", role="support")
        support.set_password(SUPPORT_PASSWORD)
        admin = User(username="admin", role="admin")
        admin.set_password(ADMIN_PASSWORD)
        demo_user = User(username="neo", role="user")
        demo_user.set_password("one")

        db.session.add_all([support, admin, demo_user])
        db.session.commit()

        # Initial message to guide students (not a spoiler)
        m = Message(sender_id=demo_user.id, content=(
            "Hey Support, my portal keeps flickering. See screenshot? "
            "Also, can you reset my password if needed? Thanks!"
        ))
        db.session.add(m)

        # Create tickets with UUIDs and crawlable structure
        tickets = []
        critical_indices = set(random.sample(range(TOTAL_TICKETS), CRITICAL_COUNT))
        admin_creds_ticket_index = random.choice(tuple(critical_indices))
        
        # Pre-generate all ticket UUIDs so we can reference them
        ticket_uuids = [str(uuid.uuid4()) for _ in range(TOTAL_TICKETS)]
        
        # Choose some tickets to contain links to critical tickets (breadcrumbs)
        critical_ticket_uuids = [ticket_uuids[i] for i in critical_indices]
        breadcrumb_indices = random.sample([i for i in range(TOTAL_TICKETS) if i not in critical_indices], min(20, TOTAL_TICKETS - CRITICAL_COUNT))

        for i in range(TOTAL_TICKETS):
            ticket_uuid = ticket_uuids[i]
            sev = "critical" if i in critical_indices else random.choices(["low", "medium", "high"], weights=[70, 20, 10])[0]
            title = make_title()
            body = ipsum(random.randint(40, 120))
            
            # Add admin credentials to one critical ticket
            if i == admin_creds_ticket_index:
                body += (
                    "\n\n[INTERNAL NOTE]\n"
                    "Escalation from Tier-2: use the fall-back admin credentials if SSO is down.\n"
                    "username: admin\n"
                    f"password: {ADMIN_PASSWORD}\n"
                    "Rotate after incident resolution."
                )
            
            # Add breadcrumb links to some tickets (helps with crawling)
            elif i in breadcrumb_indices:
                # Randomly reference critical tickets with more natural language
                referenced_uuid = random.choice(critical_ticket_uuids)
                phrases = [
                    f"\n\nSee also: Related critical issue in ticket {referenced_uuid[:8]}... (check /support/tickets/{referenced_uuid})",
                    f"\n\nEscalated to: /support/tickets/{referenced_uuid} (marked as critical)",
                    f"\n\nSimilar critical incident: {referenced_uuid[:8]}... - full details at /support/tickets/{referenced_uuid}",
                    f"\n\nREFERENCE: Critical ticket {referenced_uuid[:8]}... may contain relevant admin notes (/support/tickets/{referenced_uuid})"
                ]
                body += random.choice(phrases)
            
            # Add some cross-references between regular tickets too
            elif random.random() < 0.05:  # 5% chance
                referenced_uuid = random.choice(ticket_uuids)
                if referenced_uuid != ticket_uuid:  # Don't self-reference
                    body += f"\n\nDuplicate of: /support/tickets/{referenced_uuid}"

            t = Ticket(
                uuid=ticket_uuid,
                title=title,
                body=body,
                severity=sev,
                status="open",
                created_at=dt.datetime.utcnow() - dt.timedelta(days=random.randint(0, 20), minutes=random.randint(0, 1440))
            )
            tickets.append(t)
            db.session.add(t)
            if (i + 1) % 500 == 0:
                db.session.commit()
        db.session.commit()

        # Flag file
        with open(os.path.join(os.path.dirname(__file__), "flag.txt"), "w") as f:
            f.write("ctf{hello_there}\n")

        print("Seed complete.")
        print(f"Support login -> username: support  password: {SUPPORT_PASSWORD} (will likely get changed by CSRF)")
        print("Admin creds are hidden inside one of the critical tickets. Good hunting!")

if __name__ == "__main__":
    main()
