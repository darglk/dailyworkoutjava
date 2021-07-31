package com.darglk.dailyworkoutjava.domain.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/approvals")
public class ApprovalController {

	@Autowired
	private JdbcClientDetailsService clientDetailsService;
	
	@Autowired
	private ApprovalStore approvalStore;

	@Autowired
	private TokenStore tokenStore;
	
	@RequestMapping(value = "/list", method = RequestMethod.GET)
	public ResponseEntity<List<Approval>> myApprovals() {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		List<Approval> approvals = clientDetailsService.listClientDetails().stream()
				.map(clientDetails -> approvalStore.getApprovals(username, clientDetails.getClientId()))
				.flatMap(Collection::stream).collect(Collectors.toList());
		return ResponseEntity.ok().body(approvals);
	}
	
	@RequestMapping(value = "/delete", method = RequestMethod.POST)
	public ResponseEntity<?> revokeMyApproval(@RequestBody Approval approval) {
		String userId = SecurityContextHolder.getContext().getAuthentication().getName();
		if (approval.getUserId().equals(userId)) {
			approvalStore.revokeApprovals(Arrays.asList(approval));
			tokenStore.findTokensByClientIdAndUserName(approval.getClientId(), approval.getUserId())
					.forEach(tokenStore::removeAccessToken);
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.notFound().build();
	}
}
