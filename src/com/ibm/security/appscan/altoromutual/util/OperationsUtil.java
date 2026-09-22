package com.ibm.security.appscan.altoromutual.util;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import com.ibm.security.appscan.altoromutual.model.Account;
import com.ibm.security.appscan.altoromutual.model.User;
import com.ibm.security.appscan.altoromutual.security.SecurityUtil;

public class OperationsUtil {

	public static String doApiTransfer(HttpServletRequest request, long creditActId, long debitActId,
			double amount) {
		
		try {
			User user = OperationsUtil.getUser(request);
			String userName = user.getUsername();
			String message = DBUtil.transferFunds(userName, creditActId, debitActId, amount);
			if (message != null){
				message = "ERROR: " + message;
			} else {
				message = amount + " was successfully transferred from Account " + debitActId + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
			}
			
			return message;
			
		} catch (SQLException e) {
			return "ERROR - failed to transfer funds: " + e.getLocalizedMessage();
		}
	}
	
	
	public static String doServletTransfer(HttpServletRequest request, long creditActId, String accountIdString,
			double amount) {
		
		long debitActId = 0;

		User user = ServletUtil.getUser(request);
		String userName = user.getUsername();
		
		try {
			// Authorize transfers using the authenticated session user's accounts only
			// (never trust client-controlled cookies for account membership).
			Account[] userAccounts = user.getAccounts();
			
			Long accountId = -1L;
			try {
				accountId = Long.parseLong(accountIdString);
			} catch (NumberFormatException e) {
				//do nothing here. continue processing
			}
			
			if (accountId > 0) {
				for (Account account: userAccounts){
					if (account.getAccountId() == accountId){
						debitActId = account.getAccountId();
						break;
					}
				}
			} else {
				for (Account account: userAccounts){
					if (account.getAccountName().equalsIgnoreCase(accountIdString)){
						debitActId = account.getAccountId();
						break;
					}
				}
			}
			
		} catch (Exception e){
			//do nothing
		}
		
		//we will not send an error immediately, but we need to have an indication when one occurs...
		String message = null;
		if (creditActId < 0){
			message = "Destination account is invalid";
		} else if (debitActId <= 0) {
			message = "Originating account is invalid";
		} else if (amount < 0){
			message = "Transfer amount is invalid";
		}
		
		//if transfer amount is zero then there is nothing to do
		if (message == null && amount > 0){
			//Notice that available balance is not checked
			message = DBUtil.transferFunds(userName, creditActId, debitActId, amount);
		}
		
		if (message != null){
			message = "ERROR: " + message;
		} else {
			message = amount + " was successfully transferred from Account " + debitActId + " into Account " + creditActId + " at " + new SimpleDateFormat().format(new Date()) + ".";
		}
		
		return message;
	}

	public static String sendFeedback(String name, String email,
			String subject, String comments) {
		
		if (ServletUtil.isAppPropertyTrue("enableFeedbackRetention")) {
			long id = DBUtil.storeFeedback(name, email, subject, comments);
			return String.valueOf(id);
		}

		return null;
	}
	
	public static User getUser(HttpServletRequest request) throws SQLException{
		String authHeader = request.getHeader("Authorization");
		if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
			throw new SQLException("Missing authorization token");
		}
		String accessToken = authHeader.substring(7).trim();
		String username = SecurityUtil.resolveApiToken(accessToken);
		if (username == null) {
			throw new SQLException("Invalid or expired authorization token");
		}
		return DBUtil.getUserInfo(username);
	}
	
 }
