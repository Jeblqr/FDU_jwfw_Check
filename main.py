# Refer to https://github.com/Boreas618/FDU-Grade-Checker
from os import getenv
import re
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
import base64
import hashlib
import json
from copy import deepcopy
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header


class UISAuth:
    UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"
    )

    url_login = "https://uis.fudan.edu.cn/authserver/login?service=http://jwfw.fudan.edu.cn/eams/home.action"

    def __init__(self, uid, password):
        self.session = requests.session()
        self.session.keep_alive = False
        self.session.headers["User-Agent"] = self.UA
        self.uid = uid
        self.psw = password

    def _page_init(self):
        page_login = self.session.get(self.url_login)
        if page_login.status_code == 200:
            return page_login.text
        else:
            self.close()

    def login(self):
        page_login = self._page_init()
        data = {
            "username": self.uid,
            "password": self.psw,
            "service": "http://jwfw.fudan.edu.cn/eams/home.action",
        }

        result = re.findall(
            '<input type="hidden" name="([a-zA-Z0-9\-_]+)" value="([a-zA-Z0-9\-_]+)"/?>',
            page_login,
        )

        data.update(result)

        headers = {
            "Host": "uis.fudan.edu.cn",
            "Origin": "https://uis.fudan.edu.cn",
            "Referer": self.url_login,
            "User-Agent": self.UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

        post = self.session.post(
            self.url_login, data=data, headers=headers, allow_redirects=False
        )

        if not post.status_code == 302:
            self.close()

    def logout(self):
        exit_url = (
            "https://uis.fudan.edu.cn/authserver/logout?service=/authserver/login"
        )
        self.session.get(exit_url).headers.get("Set-Cookie")

    def close(self):
        self.logout()
        self.session.close()


class Snapshot:
    def __init__(
        self,
        gpa=0.0,
        rank=0.0,
        credits=0.0,
        class_avg=0.0,
        class_mid=0.0,
        semesterGPA=[],
        classTables=[],
    ):
        self.gpa = gpa
        self.rank = rank
        self.credits = credits
        self.class_avg = class_avg
        self.class_mid = class_mid
        self.semesterGPA = semesterGPA
        self.classTables = classTables  # 课程表（包含课程代码、名称、学分等）

    def compare(self, another_snapshot):
        if another_snapshot is None:
            return True
        return (
            self.gpa != another_snapshot.gpa
            or self.rank != another_snapshot.rank
            or self.credits != another_snapshot.credits
            or self.classTables != another_snapshot.classTables
            or self.semesterGPA != another_snapshot.semesterGPA
        )


# 定义有效格式的检查规则
def is_valid_classTable_format(entry):
    return len(entry) == 7


# 清理和过滤 classTables


def cleanClassTables(classTables):
    cleaned_class_tables = []
    for entry in classTables:
        if is_valid_classTable_format(entry):
            # 去除每个字符串中的多余标记
            cleaned_entry = [item.strip().replace("\t", "") for item in entry]
            cleaned_entry = [item.strip().replace("\n", "") for item in cleaned_entry]
            cleaned_entry = [item.strip().replace("\r", "") for item in cleaned_entry]
            cleaned_entry = [re.sub(r"\\.*", "", item) for item in cleaned_entry]
            cleaned_class_tables.append(cleaned_entry)
    return cleaned_class_tables


def is_valid_semesterGPA_format(entry):
    return len(entry) == 5


def cleanSemesterGPA(semesterGPA):
    cleaned_semesterGPA = []
    for entry in semesterGPA:
        if is_valid_semesterGPA_format(entry):
            # 去除每个字符串中的多余标记
            cleaned_entry = [item.strip().replace("\t", "") for item in entry]
            cleaned_entry = [item.strip().replace("\n", "") for item in cleaned_entry]
            cleaned_entry = [item.strip().replace("\r", "") for item in cleaned_entry]
            cleaned_entry = [re.sub(r"\\.*", "", item) for item in cleaned_entry]
            cleaned_semesterGPA.append(cleaned_entry)
    return cleaned_semesterGPA


class GradeChecker(UISAuth):
    def __init__(self, uid, password):
        super().__init__(uid, password)
        self.login()

    def get_stat(self):
        gpa_table = []
        my_gpa = 0.0
        my_credits = 0.0
        my_rank = 0.0
        class_average = 0.0
        class_mid = 0.0
        res = self.session.post(
            "https://jwfw.fudan.edu.cn/eams/myActualGpa!search.action"
        )
        if "重复登录" in res.text:
            soup = BeautifulSoup(res.text, "html.parser")
            href = soup.find("a")["href"]
            res = self.session.post(href)

        soup = BeautifulSoup(res.text, "html.parser")
        rows = soup.find_all("tr")
        for row in rows[1:]:
            columns = row.find_all("td")
            row_data = [col.get_text() for col in columns]
            gpa_table.append(row_data)

        for _, r in enumerate(gpa_table):
            class_average += float(r[5])
            if r[0] != "****":
                my_gpa, my_credits, my_rank = float(r[5]), float(r[6]), float(r[7])

        class_average = class_average / len(gpa_table)
        class_mid = float(gpa_table[int(len(gpa_table) / 2)][5])

        ################
        classTables = []
        semesterGPA = []
        raw = []
        res = self.session.post(
            "https://jwfw.fudan.edu.cn/eams/teach/grade/course/person!historyCourseGrade.action?projectType=MAJOR"
        )
        if "重复登录" in res.text:
            soup = BeautifulSoup(res.text, "html.parser")
            href = soup.find("a")["href"]
            res = self.session.post(href)
        soup = BeautifulSoup(res.text, "html.parser")
        rows = soup.find_all("tr")
        for row in rows:
            columns = row.find_all("td")
            row_data = [col.get_text() for col in columns]
            raw.append(row_data)

        semesterGPA = deepcopy(raw)
        semesterGPA = cleanSemesterGPA(semesterGPA)
        semesterGPA.sort()

        classTables = deepcopy(raw)
        classTables = cleanClassTables(classTables)
        classTables.sort()
        ###############

        return Snapshot(
            my_gpa,
            my_rank,
            my_credits,
            class_average,
            class_mid,
            semesterGPA,
            classTables,
        )


def generate_key(token: str) -> bytes:
    """
    使用token生成Fernet密钥
    确保token能生成有效的32字节密钥
    """
    # 使用token生成固定长度的密钥
    key = hashlib.sha256(token.encode()).digest()
    # 转换为Fernet可用的base64格式
    return base64.urlsafe_b64encode(key)


def encrypt_data(data: dict, token: str) -> bytes:
    """
    使用token加密数据
    """
    # 将数据转换为JSON字符串
    json_str = json.dumps(data, ensure_ascii=False)
    # 生成密钥并加密
    key = generate_key(token)
    fernet = Fernet(key)
    return fernet.encrypt(json_str.encode())


def decrypt_data(encrypted_data: bytes, token: str) -> dict:
    """
    使用token解密数据
    """
    # 生成密钥并解密
    key = generate_key(token)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    # 解析JSON数据
    return json.loads(decrypted_data.decode())


def save_snapshot(snapshot, token: str):
    """
    使用token加密保存快照数据
    """
    # 构建需要保存的数据字典
    data = {
        "my_gpa": snapshot.gpa,
        "my_rank": snapshot.rank,
        "my_credits": snapshot.credits,
        "semesterGPA": snapshot.semesterGPA if hasattr(snapshot, "semesterGPA") else [],
        "classTables": snapshot.classTables if hasattr(snapshot, "classTables") else [],
    }

    try:
        # 加密数据
        encrypted = encrypt_data(data, token)
        # 保存到文件
        with open("./record.txt", "wb+") as f:
            f.write(encrypted)
        with open("update.txt", "w+") as file:
            file.write("快照保存成功\n")
    except Exception as e:
        with open("update.txt", "w+") as file:
            file.write(f"保存快照时发生错误: {str(e)}\n")


def read_snapshot(token: str):
    """
    使用token解密读取快照数据
    """
    try:
        with open("./record.txt", "rb") as f:
            encrypted_data = f.read()
            if not encrypted_data:
                return None

            # 解密数据
            data = decrypt_data(encrypted_data, token)

            # 创建新的Snapshot对象
            snapshot = Snapshot(
                gpa=float(data["my_gpa"]),
                rank=float(data["my_rank"]),
                credits=float(data["my_credits"]),
                semesterGPA=data["semesterGPA"],
                classTables=data["classTables"],
            )

            return snapshot

    except FileNotFoundError:
        with open("update.txt", "w+") as file:
            file.write("未找到历史记录文件\n")
        return None
    except Exception as e:
        with open("update.txt", "w+") as file:
            file.write(f"读取快照时发生错误: {str(e)}\n")
        return None


def get_changes(old_snapshot, new_snapshot):
    """详细比较两个快照的所有差异"""
    changes = []

    # 基础数据比较
    if old_snapshot is None:
        changes.extend(
            [
                ("基础信息", "GPA", f"初始值 → {new_snapshot.gpa:.2f}"),
                ("基础信息", "排名", f"初始值 → {int(new_snapshot.rank)}"),
                ("基础信息", "总学分", f"初始值 → {new_snapshot.credits:.1f}"),
            ]
        )
        # 添加所有课程作为新增
        for course in new_snapshot.classTables:
            changes.append(("新增课程", *course))  # 新增课程
        # 添加所有学期GPA作为新增
        for sem in new_snapshot.semesterGPA:
            changes.append(
                ("新增学期", str(sem[0]) + " " + str(sem[1]), sem[2], sem[3], sem[4])
            )
    else:
        # 比较基础数据
        if old_snapshot.gpa != new_snapshot.gpa:
            changes.append(
                ("基础信息", "GPA", f"{old_snapshot.gpa:.2f} → {new_snapshot.gpa:.2f}")
            )
        if old_snapshot.rank != new_snapshot.rank:
            changes.append(
                (
                    "基础信息",
                    "排名",
                    f"{int(old_snapshot.rank)} → {
                           int(new_snapshot.rank)}",
                )
            )
        if old_snapshot.credits != new_snapshot.credits:
            changes.append(
                (
                    "基础信息",
                    "总学分",
                    f"{old_snapshot.credits:.1f} → {
                           new_snapshot.credits:.1f}",
                )
            )

        # 比较课程数据
        # 使用课程代码作为字典键
        old_courses = {course[1]: course for course in old_snapshot.classTables}
        # 使用课程代码作为字典键
        new_courses = {course[1]: course for course in new_snapshot.classTables}

        # 查找新增课程
        for course_code, course in new_courses.items():
            if course_code not in old_courses:
                changes.append(("新增课程", *course))  # 新增课程

        # 查找更新课程
        for course_code, old_course in old_courses.items():
            if course_code in new_courses:
                new_course = new_courses[course_code]
                if old_course != new_course:
                    changes.append(
                        (
                            "更新课程",
                            old_course[3],
                            f"从 {old_course[4]} 学分 {
                                   old_course[6]} 变为 {new_course[4]} 学分 {new_course[6]}",
                        )
                    )

        # 比较学期GPA数据
        old_semester_gpa = {
            f"{sem[0]} {
            sem[1]}": sem
            for sem in old_snapshot.semesterGPA
        }  # 使用学年和学期作为字典键
        new_semester_gpa = {
            f"{sem[0]} {
            sem[1]}": sem
            for sem in new_snapshot.semesterGPA
        }  # 使用学年和学期作为字典键

        # 查找新增学期GPA
        for sem_key, sem in new_semester_gpa.items():
            if sem_key not in old_semester_gpa:
                changes.append(("新增学期", sem_key, sem[2], sem[3], sem[4]))

        # 查找更新学期GPA
        for sem_key, old_sem in old_semester_gpa.items():
            if sem_key in new_semester_gpa:
                new_sem = new_semester_gpa[sem_key]
                if old_sem != new_sem:
                    changes.append(
                        (
                            "更新学期",
                            sem_key,
                            f"学期GPA从 {
                                   old_sem[4]} 变为 {new_sem[4]}",
                        )
                    )

    return changes


def generate_html_content(changes):
    """生成基于变化的HTML内容"""
    html_content = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h2 { color: #4CAF50; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            table, th, td { border: 1px solid #ddd; }
            th, td { padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .change { color: #ff5722; }
            .added { color: #4CAF50; }
        </style>
    </head>
    <body>
        <h2>成绩和课程变化通知</h2>
    """

    # 分开处理不同类别的变化
    added_courses = []
    updated_courses = []
    added_semesters = []
    updated_semesters = []
    basic_info_changes = []

    # 分类存储变化
    for change in changes:
        if change[0] == "新增课程":
            added_courses.append(change)
        elif change[0] == "更新课程":
            updated_courses.append(change)
        elif change[0] == "新增学期":
            added_semesters.append(change)
        elif change[0] == "更新学期":
            updated_semesters.append(change)
        elif change[0] == "基础信息":
            basic_info_changes.append(change)

    # 显示基础信息变化
    if basic_info_changes:
        html_content += "<h3>基础信息变化</h3>"
        html_content += "<table>"
        html_content += "<tr><th>item</th><th>changes</th></tr>"
        for change in basic_info_changes:
            html_content += f"<tr><td>{change[1]
                                       }</td><td>{change[2]}</td></tr>"
        html_content += "</table>"

    # 显示新增课程
    if added_courses:
        html_content += "<h3>新增课程</h3>"
        html_content += "<table>"
        html_content += "<tr><th>学期</th><th>课程名称</th><th>课程代码</th><th>学分</th><th>成绩</th><th>绩点</th></tr>"
        for course in added_courses:
            html_content += f"""
            <tr class="added">
                <td>{course[1]}</td>
                <td>{course[4]}</td>
                <td>{course[3]}</td>
                <td>{course[5]}</td>
                <td>{course[6]}</td>
                <td>{course[7]}</td>
            </tr>
            """
        html_content += "</table>"

    # 显示更新的课程
    if updated_courses:
        html_content += "<h3>更新课程</h3>"
        html_content += "<table>"
        html_content += "<tr><th>课程名称</th><th>变化内容</th></tr>"
        for course in updated_courses:
            html_content += f"""
            <tr class="change">
                <td>{course[1]}</td>
                <td>{course[2]}</td>
            </tr>
            """
        html_content += "</table>"

    # 显示新增学期GPA
    if added_semesters:
        html_content += "<h3>新增学期GPA</h3>"
        html_content += "<table>"
        html_content += (
            "<tr><th>学期</th><th>课程门数</th><th>总学分</th><th>学期GPA</th></tr>"
        )
        for semester in added_semesters:
            html_content += f"""
            <tr class="added">
                <td>{semester[1]}</td>
                <td>{semester[2]}</td>
                <td>{semester[3]}</td>
                <td>{semester[4]}</td>
            </tr>
            """
        html_content += "</table>"

    # 显示更新的学期GPA
    if updated_semesters:
        html_content += "<h3>更新学期GPA</h3>"
        html_content += "<table>"
        html_content += "<tr><th>学期</th><th>变化内容</th></tr>"
        for semester in updated_semesters:
            html_content += f"""
            <tr class="change">
                <td>{semester[1]}</td>
                <td>{semester[2]}</td>
            </tr>
            """
        html_content += "</table>"

    html_content += "</body></html>"

    return html_content


def send_email_notification(changes, sender_email, sender_password, receiver_email):
    """发送邮件通知"""
    if not changes:
        return

    # 邮件服务器配置（需要配置）
    smtp_server = "smtp.qq.com"
    smtp_port = 587

    # 创建邮件
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(f"复旦大学成绩更新提醒 - {len(changes)}项变更", "utf-8")
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # 生成HTML内容
    html_content = generate_html_content(changes)
    msg.attach(MIMEText(html_content, "html", "utf-8"))
    with open("update.txt", "w+") as file:
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            file.write("成绩更新邮件已发送\n")
        except Exception as e:
            file.write(f"发送邮件时出错: {str(e)}\n")


if __name__ == "__main__":
    with open("update.txt", "w") as file:
        file.write('')
    uid, psw, token, sender_email, sender_email_pwd, receiver_email = (
        getenv("STD_ID"),
        getenv("PASSWORD"),
        getenv("TOKEN"),
        getenv("SENDER"),
        getenv("SENDER_PWD"),
        getenv("RECEIVER"),
    )
    assert (
        uid and psw and token and sender_email and sender_email_pwd and receiver_email
    )
    checker = GradeChecker(uid, psw)
    new_snapshot = checker.get_stat()
    checker.close()

    old_snapshot = read_snapshot(token)
    changes = get_changes(old_snapshot, new_snapshot)

    if changes:
        save_snapshot(new_snapshot, token)
        send_email_notification(changes, sender_email, sender_email_pwd, receiver_email)
        with open("update.txt", "w+") as file:
            file.write(f"检测到{len(changes)}项成绩更新")
        print("update")
