#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <thread>
#include <queue>
#include <future>
#include <mutex>
#include <condition_variable>

using namespace std;


// class Task {
// 	public:
// 	template<typename F, class... Args>
// 		Task(F&& f, Args&&... args):func(bind(forward<F>(f), forward<Args>(args)...)) { cout<< "create Task:"<<std::this_thread::get_id()<<endl;}
// 	void execute() { 
// 		if (func)
// 		{
// 			cout<< "Task..."<<endl;
// 			func();
// 		}
// 	}

// 	private:
// 	function<void()> func;
// };


// int add(int a, int b) {
// 	cout << " a + b"<<endl;
// 	return a + b;
// }


class ThreadPool {
	public:
	ThreadPool(size_t numThreads);
	~ThreadPool();

	template<typename F, class... Args>
	auto enqueue(F&& f, Args&&... args) -> future<typename result_of<F(Args...)>::type>;

	private:
	void worker();

	vector<thread> threads;
	queue<function<void()>> tasks;
	mutex queue_mutex;
	condition_variable cv;

	bool stop;
};

ThreadPool::ThreadPool(size_t numThreads) : stop(false) {
	for (size_t i = 0; i < numThreads; ++i){
		threads.emplace_back([this] {
			while (true)
			{			
			function<void()> task;
			{
				unique_lock<mutex> lock(queue_mutex);
				cout<<"tasks:"<< tasks.size()<<endl;
				cv.wait(lock, [this]{ return this->stop || !this->tasks.empty(); });
				if (stop && tasks.empty()) {
					return;
				}
				task = move(tasks.front());
				tasks.pop();
				cout<<"tasks2:"<< tasks.size()<<endl;
			}
			task();
			}
		});
		//cout<<"threads:"<< threads.size()<<endl;
	}

		//cout<<"threads2:"<< threads.size()<<endl;
		//threads.emplace_back([this] { this->worker(); });
		//cout<<"threads2:"<< threads.size()<<endl;
}

ThreadPool::~ThreadPool(){
 {
 	std::unique_lock<std::mutex> lock(queue_mutex);
 	stop = true;
}
	cv.notify_all();
	for (std::thread& thread : threads) {
		thread.join();
	}
}

// template<class F, class... Args>
// auto ThreadPool::enqueue(F&& f, Args&&... args)->future<typename result_of<F(Args...)>::type> {
// 	using return_type = typename result_of<F(Args...)>::type;
// 	//auto task = make_unique<Task>(forward<F>(f), forward<Args>(args)...);
// 	auto task = make_shared<packaged_>(forward<F>(f), forward<Args>(args)...);
// 	{
// 		unique_lock<mutex> lock(queue_mutex);
// 		if (stop) {
// 			throw runtime_error("enqueue on stopped ThreadPool");
// 		}
// 		tasks.push(move(task));
// 	}
// 	cv.notify_one();
// }
template<class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
	using return_type = typename std::result_of<F(Args...)>::type;
	auto task = std::make_shared<std::packaged_task<return_type()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
	std::future<return_type> res = task->get_future();
	{
		std::unique_lock<std::mutex> lock(queue_mutex);
		if (stop)
			throw std::runtime_error("enqueue on stopped ThreadPool");
		tasks.emplace([task]() { (*task)(); });
	}
	cv.notify_one();
	return res;
}

void ThreadPool::worker() {
	// while (true) {
	// 	unique_ptr<Task> task;
	// 	{
	// 		unique_lock<mutex> lock(queue_mutex);
	// 		cv.wait(lock, [this]{ return stop || !tasks.empty(); });
	// 		if (stop && tasks.empty()) {
	// 			return;
	// 		}
	// 		task = move(tasks.front());
	// 		tasks.pop();
	// 	}
	// 	task->execute();
	// }
}

// 定义一个简单的任务函数
void simpleTask(int num) {
	std::this_thread::sleep_for(std::chrono::seconds(1));
	std::cout << "Task " << num << " executed by thread " << std::this_thread::get_id() << std::endl;
	//std::this_thread::sleep_for(std::chrono::seconds(1));
}

int main()
{
	// queue<function<void()>> tasks;//task 任务队列，用于存储待执行的任务
	// mutex queue_mutex;
	// condition_variable cv;
	// auto threadCount = 5;
	// std::vector<std::thread> threads;
	// for (size_t i = 0; i < threadCount; i++)
	// {
	// 	threads.emplace_back([this]() {
	// 		std::cout << "Thread " << std::this_thread::get_id() << " -->" << this->get_id()<< " started" << std::endl;
	// 		this->work();
	// 	})
	// }
	// Task task(add, 1, 2);
	// task.execute();
	ThreadPool pool(1);

	for (int i = 0; i < 100; i++)
	{
		pool.enqueue(simpleTask, i);
	}

	std::this_thread::sleep_for(std::chrono::seconds(10));
	return 0;
}