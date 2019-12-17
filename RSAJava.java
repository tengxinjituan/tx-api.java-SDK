import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * API加密接口测试用例仅供参考 需要引用org.apache.commons.codec jar包
 */
public class RSAJava {
	public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
	public static final String CHAR_ENCODING = "UTF-8";
	public static final String ACCOUNT = "账号";
	public static final String PASSWORD = "密码";
	public static final String UID = "产品编号";
	public static String URL = "http://IP:端口";

	public static void main(String[] args) throws Exception {

		String[] type = { "send", "variable", "balance", "mo", "report", "sendpackage" };
		String pubKey = "公钥,向客服或业务人员或短信平台获取";

		/*
		 * 此处使用AES-128-ECB加密模式，key需要为16位，可以自定义。
		 */
		String cKey = "1234567890123456";
		// 加密key
		String encryptkey = RAS_encrypt(cKey, pubKey);
		System.out.println("密文:\n" + encryptkey);
		for (String string : type) {

			// 需要加密的字串
			String cSrc = GetStr(string);
			System.out.println(cSrc);
			// 加密
			String enString = AES_Encrypt(cSrc, cKey);
			System.out.println("加密后的字串是：" + enString);

			String json = "";
			String result = "";
			// API加密接口地址
			String url = URL + GetAPIMethod(string) + "/rsa";
			if (string == "sendpackage") {
				json = "key=" + URLEncoder.encode(encryptkey, "UTF-8") + "&data=" + URLEncoder.encode(enString, "UTF-8")
						+ "&account=" + ACCOUNT;
				result = post2(url, json);
			} else {
				json = "{\"key\":\"" + encryptkey + "\",\"data\":\"" + enString + "\",\"account\":\"" + ACCOUNT + "\"}";
				result = post(url, json);
			}

			System.out.println("json:\n" + json);
			System.out.println("result:" + result);

		}

	}

	/**
	 * 获取接口方法
	 */
	public static String GetAPIMethod(String type) {
		String str = "";
		switch (type) {
		case "send":
			str = "/msg/send/json";
			break;
		case "variable":
			str = "/msg/variable/json";
			break;
		case "balance":
			str = "/msg/balance/json";
			break;
		case "mo":
			str = "/msg/pull/mo";
			break;
		case "report":
			str = "/msg/pull/report";
			break;
		case "sendpackage":
			str = "/msg/sendpackage/json";
			break;
		}
		return str;
	}

	/**
	 * 获取不同接口的json拼接字符串
	 */
	public static String GetStr(String type) {
		String str = "";
		switch (type) {
		case "send":
			str = "{\"account\":\"" + ACCOUNT + "\",\"password\":\"" + PASSWORD
					+ "\",\"msg\":\"您的验证码是：6690\",\"phone\":\"发送的手机号\",\"sendtime\":\"201704101400\",\"report\":\"true\",\"extend\":\"555\",\"uid\":\""
					+ UID + "\",\"format\":\"json\",\"useragent\":\"http\"}";
			break;
		case "variable":
			str = "{\"account\":\"" + ACCOUNT + "\",\"password\":\"" + PASSWORD
					+ "\",\"msg\":\"验证码短信{$var}你好，{$var}请你于{$var}日参加考试\",\"params\":\"发送的手机号,张三1,男,19;发送的手机号,张三2,女,20\",\"sendtime\":\"\",\"report\":\"true\",\"extend\":\"123\",\"uid\":\""
					+ UID + "\",\"format\":\"json\",\"useragent\":\"http\"}";
			break;
		case "balance":
			str = "{\"account\":\"" + ACCOUNT + "\",\"password\":\"" + PASSWORD + "\",\"uid\":\"" + UID
					+ "\",\"format\":\"\"}";
			break;
		case "mo":
		case "report":
			str = "{\"account\":\"" + ACCOUNT + "\",\"password\":\"" + PASSWORD + "\",\"uid\":\"" + UID + "\",\"count\":20,\"format\":\"xml\"}";
			break;
		case "sendpackage":
			str = "account=" + ACCOUNT + "&password=" + PASSWORD
					+ "&msg=发送的手机号|测试短信1&msg=发送的手机号|测试短信2&msg=发送的手机号|测试短信3&sendtime=201704101400&report=true&extend=555&uid="
					+ UID + "&format=json&useragent=http";
			break;
		default:
			break;
		}
		return str;
	}

	/**
	 * 得到公钥
	 * 
	 * @param key
	 *            密钥字符串（经过base64编码）
	 * @throws Exception
	 */
	public static PublicKey RAS_getPublicKey(String key) throws Exception {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(key.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	/**
	 * 加密方法
	 */
	public static String RAS_encrypt(String source, String publicKey) throws Exception {
		Key key = RAS_getPublicKey(publicKey);
		/** 得到Cipher对象来实现对源数据的RSA加密 */
		Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] b = source.getBytes();
		/** 执行加密操作 */
		byte[] b1 = cipher.doFinal(b);
		return new String(Base64.encodeBase64(b1), CHAR_ENCODING);
	}

	/**
	 * AES加密方法
	 */
	public static String AES_Encrypt(String sSrc, String sKey) throws Exception {
		if (sKey == null) {
			System.out.print("Key为空null");
			return null;
		}
		// 判断Key是否为16位
		if (sKey.length() != 16) {
			System.out.print("Key长度不是16位");
			return null;
		}
		byte[] raw = sKey.getBytes("utf-8");
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");// "算法/模式/补码方式"
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));

		return new Base64().encodeToString(encrypted);// 此处使用BASE64做转码功能，同时能起到2次加密的作用。
	}

	/**
	 * 发送HttpPost请求
	 * 
	 * @param strURL
	 *            服务地址
	 * @param params
	 *            json字符串,例如: "{ \"id\":\"12345\" }" ;其中属性名必须带双引号<br/>
	 * @return 成功:返回json字符串<br/>
	 */
	public static String post(String strURL, String params) {
		System.out.println(strURL);
		System.out.println(params);
		BufferedReader reader = null;
		try {
			URL url = new URL(strURL);// 创建连接
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setUseCaches(false);
			connection.setInstanceFollowRedirects(true);
			connection.setRequestMethod("POST"); // 设置请求方式
			// connection.setRequestProperty("Accept", "application/json"); //
			// 设置接收数据的格式
			connection.setRequestProperty("Content-Type", "application/json"); // 设置发送数据的格式
			connection.connect();
			// 一定要用BufferedReader 来接收响应， 使用字节来接收响应的方法是接收不到内容的
			OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream(), "UTF-8"); // utf-8编码
			out.append(params);
			out.flush();
			out.close();
			// 读取响应
			reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
			String line;
			String res = "";
			while ((line = reader.readLine()) != null) {
				res += line;
			}
			reader.close();
			return res;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "error"; // 自定义错误信息
	}

	public static String post2(String strURL, String params) {

		try {
			URL url = new URL(strURL);
			byte[] postDataBytes = params.toString().getBytes("UTF-8");

			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
			conn.setDoOutput(true);
			conn.getOutputStream().write(postDataBytes);

			Reader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));

			StringBuilder sb = new StringBuilder();
			for (int c; (c = in.read()) >= 0;)
				sb.append((char) c);
			String response = sb.toString();
			System.out.println(response);
			return response;

		} catch (Exception e) {
			// TODO: handle exception
		}

		return "err";
	}
}
