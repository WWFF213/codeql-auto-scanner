import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Main {

    // 漏洞点：用户输入直接拼接到 SQL 字符串后执行
    public void search(HttpServletRequest req, Connection conn) throws SQLException {
        String name = req.getParameter("name");                    // source
        String sql = "SELECT * FROM users WHERE name='" + name + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);                                    // sink
    }

    // 对照组：使用 PreparedStatement，安全写法，不应被告警
    public void searchSafe(HttpServletRequest req, Connection conn) throws SQLException {
        String name = req.getParameter("name");
        java.sql.PreparedStatement ps =
            conn.prepareStatement("SELECT * FROM users WHERE name=?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
