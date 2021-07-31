package com.darglk.dailyworkoutjava.domain.user.response;

import lombok.Data;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class ModelValidationError {
	private Map<String, List<String>> errors = new HashMap<>();
}
