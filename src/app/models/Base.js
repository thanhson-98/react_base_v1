import superagent from 'superagent';
import publicIp from 'public-ip';
import Cookie from 'js-cookie';
import { isObject, omit } from 'opLodash';
import { v4 } from 'uuid';

/* ------- ENV VARIABLE ------ */
// export const API_ROOT = "http://localhost:3000";
// export const OAUTH_ROOT = "http://localhost:3000/auth-server";

export const API_ROOT = process.env.REACT_APP_SERVER_API;
export const OAUTH_ROOT = process.env.REACT_APP_SERVER_OAUTH;
const USERNAME = process.env.REACT_APP_SERVER_USERNAME;
const PASSWORD = process.env.REACT_APP_SERVER_PASSWORD;

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

export const setFacebookToken = (token, ttl) => {
	if (token) {
		Cookie.set('facebookToken', JSON.stringify(token), {
			expires: ttl / (24 * 60 * 60),
			// secure: true,
			sameSite: 'Lax',
		});
	} else {
		Cookie.remove('facebookToken');
	}
};

const getVnptToken = () => Cookie.get('vnptToken');

const setToken = (access) => {
	if (access) {
		Cookie.set('access', JSON.stringify('sessionInfo'), {
			expires: (access.expires_in / 24) * 60 * 60,
			// secure: true,
			sameSite: 'Lax',
		});
		Cookie.set('refresh_token', access.refresh_token || refreshToken, {
			expires: 30,
			// secure: true,
			sameSite: 'Lax',
		});
	} else {
		Cookie.remove('access');
		Cookie.remove('refresh_token');
		accessInfo = null;
		refreshToken = null;
		localStorage.removeItem('user');
	}
};

export const clearToken = () => setToken(null);

// http inject, parse
const responseBody = (res) => (res.body ? res.body : res.text);

const responseBodyPost = (res) => res;

const tokenPlugin = (req) => {
	parseAccess();
	if (accessInfo) {
		req.set('Authorization', `Bearer ${accessInfo.access_token}`);
	}
};

//catch error
export const catchError = (e) => {
	let error = e.response?.body.error;
	if (!isObject(error)) {
		error = e.response?.body || e?.response || {};
	}
	error.status = e.status;
	let statusAccount = '';
	if (error.error_description === 'User is not activated') {
		statusAccount = 'NOT_ACTIVE';
		// store.dispatch(
		// 	appActions.updateUser({
		// 		statusAccount,
		// 	}),
		// );
		error.dontCatchError = true;
	} else if (
		error.errorCode === 'error.user.disable' ||
		error.error_code === 'error.user.inactive' ||
		error.error_description === 'User is disabled'
	) {
		statusAccount = 'IN_ACTIVE';
		// store.dispatch(
		// 	appActions.updateUser({
		// 		statusAccount,
		// 	}),
		// );
		error.dontCatchError = true;
		setToken();
	} else if (
		e.status === 403 ||
		error.errorCode === 'error.ticket.user.not.be.supporter' ||
		error.errorCode === 'error.ticket.sme.not.be.owner' ||
		error.errorCode === 'error.department.user.not.own' ||
		(error.errorCode === 'error.no.have.access' && error.object === 'customer_ticket')
	) {
		statusAccount = 'DENIED';
		// store.dispatch(appActions.changeStatus(statusACCOUNT));
		error.dontCatchError = true;
	} else if (
		!error.field &&
		!error.fields &&
		!e.response?.error?.url?.includes('/auth-server/api/users-sme/import/users') &&
		!e.response?.error?.url?.includes('/auth-server/api/users-sme/import-url/users') &&
		!error?.error?.url?.includes('/admin-portal/email-template/')
	) {
		// notification.error({
		// 	message: 'Đã có lỗi xảy ra, vui lòng thử lại sau ít phút.',
		// });
	}
	throw error;
};

//auth http
export const getTokenByUsernamePassword = async (data) => {
	if (data.access_token) {
		setToken(data);
		return data;
	}
	const res = await superagent
		.post(`${OAUTH_ROOT}/oauth/token`, {
			...data,
			grant_type: 'password',
			scope: accessInfo?.scope || v4(),
		})
		.type('form')
		.auth(USERNAME, PASSWORD)
		.then(responseBody)
		.catch(catchError);
	setToken(res);
	return res;
};
