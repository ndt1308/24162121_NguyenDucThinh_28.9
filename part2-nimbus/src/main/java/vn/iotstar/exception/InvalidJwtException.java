package vn.iotstar.exception;

/** Loi khi doc / xac thuc JWT bang Nimbus (mot RuntimeException de filter va handler xu ly chung). */
public class InvalidJwtException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public enum Reason {
        MALFORMED,          // sai dinh dang, thieu claim, sai thuat toan
        INVALID_SIGNATURE,  // chu ky khong khop (token bi sua)
        EXPIRED             // het han (exp)
    }

    private final Reason reason;

    public InvalidJwtException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidJwtException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
