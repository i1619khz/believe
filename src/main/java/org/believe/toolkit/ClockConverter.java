package org.believe.toolkit;

import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * @author WangYi
 * @since 2019/6/20
 */
@Component
public class ClockConverter {

	private final ZoneId zoneId = ZoneId.systemDefault();

	/**
	 * LocalDateTime转Date
	 *
	 * @param localDateTime
	 * @return
	 */
	public Date localDateTimeToDate(final LocalDateTime localDateTime) {
		return Date.from(localDateTime.atZone(zoneId).toInstant());
	}

	/**
	 * LocalDate转Date
	 *
	 * @param localDate
	 * @return
	 */
	public Date localDateToDate(final LocalDate localDate) {
		return Date.from(localDate.atStartOfDay(zoneId).toInstant());
	}

	/**
	 * Date转LocalDateTime
	 *
	 * @param date
	 * @return
	 */
	public LocalDateTime dateToLocalDateTime(final Date date) {
		return date.toInstant().atZone(zoneId).toLocalDateTime();
	}

	/**
	 * Date转LocalDate
	 *
	 * @param date
	 * @return
	 */
	public LocalDate dateToLocalDate(final Date date) {
		return dateToLocalDateTime(date).toLocalDate();
	}

	/**
	 * 字符串转LocalDate
	 *
	 * @param str
	 * @return
	 */
	public LocalDate strToLocalDate(final String str) {
		return LocalDate.parse(str);
	}
}
