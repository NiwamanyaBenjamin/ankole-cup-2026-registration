ANKOLE CUP 2026 PROFESSIONAL PLAYER REGISTRATION SYSTEM - VERSION 5

HOW TO RUN
1. Open this folder in VS Code or CMD.
2. Run: npm install
3. Run: node server.js
4. Open: http://localhost:3000

ADMIN LOGIN
Username: admin
Password: 1234

IMPORTANT: Change the admin password immediately after first login.
The default admin account is not displayed anywhere in the public system.

NEW PROFESSIONAL FEATURES IN V5
- Ankole Cup logo on the online form and generated PDF documents.
- Kashari added to the district list.
- District officer accounts.
- Main admin can create district officer accounts.
- District officers can only see players from their own district.
- Professional player status workflow: Pending, Under Review, Verified, Approved, Rejected, Suspended.
- Duplicate NIN prevention.
- Strict NIN format validation.
- National ID front and back upload.
- Player photo upload.
- Official PDF registration form download.
- Player ID card PDF download.
- QR code on generated documents/cards.
- Registration deadline control.
- Audit log for important admin actions.
- Database backup button.
- CSV and JSON export routes are still inside the system but hidden from the dashboard.

NOTE ABOUT NIN VALIDATION
The system validates the NIN format and prevents duplicate NIN submissions.
Real confirmation from NIRA/government records requires official API access.
