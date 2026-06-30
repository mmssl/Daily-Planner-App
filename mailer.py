"""
mailer.py — Gmail SMTP ile e-posta gönderme
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 465  # SSL


def _get_config():
    return {
        'username': os.getenv('MAIL_USERNAME', ''),
        'password': os.getenv('MAIL_PASSWORD', ''),
        'from_name': os.getenv('MAIL_FROM_NAME', 'Görev Takip'),
    }


def send_email(to_email: str, subject: str, html_body: str) -> bool:
    """
    Tek bir e-posta gönderir. Başarılıysa True döner.
    Hata olursa False döner ve konsola yazar (uygulamayı çökertmez).
    """
    cfg = _get_config()
    if not cfg['username'] or not cfg['password']:
        print("[mailer] UYARI: MAIL_USERNAME / MAIL_PASSWORD ayarlanmamış. E-posta gönderilmedi.")
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{cfg['from_name']} <{cfg['username']}>"
    msg['To'] = to_email
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            server.login(cfg['username'], cfg['password'])
            server.sendmail(cfg['username'], to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[mailer] E-posta gönderilemedi ({to_email}): {e}")
        return False


# ── E-posta şablonları ───────────────────────────────────────
def _wrap(inner_html: str) -> str:
    """Ortak HTML şablon çerçevesi."""
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:Segoe UI,Arial,sans-serif;">
  <div style="max-width:480px;margin:30px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);">
    <div style="background:linear-gradient(135deg,#0060cc,#007fff,#339dff);padding:24px;text-align:center;">
      <div style="font-size:32px;">📋</div>
      <div style="color:#fff;font-size:18px;font-weight:700;margin-top:4px;">Görev Takip</div>
    </div>
    <div style="padding:28px 32px;color:#1a2332;">
      {inner_html}
    </div>
    <div style="padding:16px 32px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px;text-align:center;">
      Bu e-posta Görev Takip uygulaması tarafından otomatik gönderilmiştir.
    </div>
  </div>
</body>
</html>"""


def verification_email(code: str) -> tuple:
    """Kayıt doğrulama kodu e-postası. (subject, html) döner."""
    inner = f"""
      <h2 style="font-size:18px;margin:0 0 12px;">E-posta Adresinizi Doğrulayın</h2>
      <p style="font-size:14px;color:#64748b;line-height:1.6;margin:0 0 20px;">
        Hesabınızı etkinleştirmek için aşağıdaki doğrulama kodunu uygulamaya girin:
      </p>
      <div style="background:#f0f7ff;border:2px solid #007fff;border-radius:10px;
                  padding:18px;text-align:center;margin:0 0 20px;">
        <span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#007fff;font-family:monospace;">
          {code}
        </span>
      </div>
      <p style="font-size:12px;color:#94a3b8;margin:0;">
        Bu kod 15 dakika geçerlidir. Bu işlemi siz yapmadıysanız bu e-postayı yok sayabilirsiniz.
      </p>
    """
    return ("Görev Takip — E-posta Doğrulama Kodu", _wrap(inner))


def reminder_email(user_email: str, gorevler: list) -> tuple:
    """Yaklaşan görev hatırlatması. gorevler: [{'text':..,'due':..}] """
    items = ""
    for g in gorevler:
        items += f"""
          <div style="background:#fff8f0;border-left:3px solid #f39c12;border-radius:6px;
                      padding:12px 14px;margin-bottom:8px;">
            <div style="font-size:14px;font-weight:600;color:#1a2332;">⏰ {g['text']}</div>
            <div style="font-size:12px;color:#e74c3c;margin-top:4px;">Bitiş: {g['due']}</div>
          </div>"""
    inner = f"""
      <h2 style="font-size:18px;margin:0 0 12px;">Yaklaşan Görevleriniz</h2>
      <p style="font-size:14px;color:#64748b;line-height:1.6;margin:0 0 18px;">
        Aşağıdaki görevlerin bitiş tarihi yaklaşıyor:
      </p>
      {items}
      <p style="font-size:12px;color:#94a3b8;margin:16px 0 0;">
        Görevlerinizi tamamlamayı unutmayın! 💪
      </p>
    """
    n = len(gorevler)
    return (f"Görev Takip — {n} göreviniz yaklaşıyor ⏰", _wrap(inner))
