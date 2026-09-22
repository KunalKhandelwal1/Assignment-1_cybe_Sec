def page(title: str, content: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title} - Classmate Hub</title>
  <link rel="stylesheet" href="/public/style.css">
</head>
<body>
  <div class="wrapper">
    <div class="card">
      {content}
    </div>
  </div>
</body>
</html>"""
