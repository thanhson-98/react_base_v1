import superagent from 'superagent';
import publicIp from 'public-ip';
import Cookie from 'js-cookie';

/* ------- ENV VARIABLE ------ */
// export const API_ROOT = "http://localhost:3000";
// export const OAUTH_ROOT = "http://localhost:3000/auth-server";

export const API_ROOT = process.env.REACT_APP_SERVER_API;
export const OAUTH_ROOT = process.env.REACT_APP_SERVER_OAUTH;

// token defined
let accessInfo;
let refreshToken;

export const parseAccess = () => {
	try {
		accessInfo = JSON.parse(Cookie.get('access'));
		refreshToken = Cookie.get('refresh_token');
	} catch (error) {
		accessInfo = null;
	}
};
parseAccess();

export const getAccessToken = () => {
	parseAccess();
	return accessInfo?.access_token || '';
};

export const setVnptToken = (token, ttl) => {
	if (token) {
		Cookie.set('vnptToken', JSON.stringify(token), {
			expires: ttl / (24 * 60 * 60),
			// secure: true,
			sameSite: 'Lax',
		});
	} else {
		Cookie.remove('vnptToken');
	}
};

export const setGoogleToken = (token, ttl) => {
	if (token) {
		Cookie.set('googleToken', JSON.stringify(token), {
			expires: ttl / (24 * 60 * 60),
			// secure: true,
			sameSite: 'Lax',
		});
	} else {
		Cookie.remove('googleToken');
	}
};
