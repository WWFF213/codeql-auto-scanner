import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FileServlet extends HttpServlet {

    // 漏洞点：用户输入未校验直接拼接成路径
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");           // source
        File f = new File("/var/data/" + filename);           // sink: 可被 ../ 绕过
        try (FileInputStream fis = new FileInputStream(f)) {
            resp.getOutputStream().write(fis.readAllBytes());
        }
    }

    // 对照组：用 getCanonicalPath 校验路径在白名单目录内
    public void doGetSafe(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        File base = new File("/var/data/").getCanonicalFile();
        File f = new File(base, filename).getCanonicalFile();
        if (!f.getPath().startsWith(base.getPath())) {
            resp.sendError(403);
            return;
        }
        try (FileInputStream fis = new FileInputStream(f)) {
            resp.getOutputStream().write(fis.readAllBytes());
        }
    }
}
