from requests import post


def send_verification_email(email: str, verification_code: str, expiration_minutes: int) -> None:
    """
    Function to send a verification email to the user's email.
    Using my own internal service to send the email.

    :param email: The email to send the verification email to.
    :param verification_code: The verification code to include in the email.
    :param expiration_minutes: The expiration time of the verification code.
    """
    url = "http://192.168.1.99:29998/email"
    data = {
        "recipient": email,
        "subject": "Rei's Chatroom - Verify your email",
        "plain": "Your Verification Code is: " + verification_code,
        "html": "<table width=\"100%\" style=\"max-width: 600px; margin: auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 2px 5px rgba(0,0,0,0.1);\"> <tr> <td align=\"center\"> <h2 style=\"color: #007bff;\">Rei\'s Chatroom</h2> <p style=\"font-size: 16px; color: #555;\">Your verification code is:</p> <p style=\"font-size: 24px; font-weight: bold; color: #007bff; background: #f0f8ff; padding: 10px 20px; border-radius: 5px; display: inline-block;\"> " + verification_code + " </p> <p>This code will expire in " + str(
            str(expiration_minutes)) + " minutes.</p> <p style=\"color: #777;\">If you didn\'t request this code, please ignore this email.</p> </td> </tr> <tr> <td align=\"center\" style=\"padding-top: 20px; border-top: 1px solid #ddd;\"> <p style=\"font-size: 12px; color: #777;\"> Need help? Contact me at <a href=\"mailto:akbar@reishandy.my.id\" style=\"color: #007bff; text-decoration: none;\">akbar@reishandy.my.id</a> </p> <p style=\"font-size: 12px; color: #888;\"> <em>Legal Disclaimer:</em> This email may contain confidential information. If you are not the intended recipient, please delete it immediately. </p> </td> </tr></table>"
    }

    # Send the data using a requests's POST
    response = post(url, json=data)
    if response.status_code != 201:
        raise RuntimeError("Failed to send verification email")