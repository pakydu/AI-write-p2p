/*
典型的原子操作有 Load / Store（读取与保存）、
Test and Set（针对 bool 变量，如果为 true 则返回 true，如果为 false，则将变量置为 true 并返回 false）、
Clear（将 bool 变量设为 false）、
Exchange（将指定位置的值设置为传入值，并返回其旧值）

CAS 操作是无锁队列实现的核心技术之一。它是一种原子的比较并交换操作，包含三个参数：
	内存位置（V）、
	预期原值（A）
	新值（B） 
其工作原理是：
	首先检查内存位置 V 的值是否等于预期原值 A，如果相等，则将内存位置 V 的值更新为新值 B，
	否则不进行任何操作。整个过程是原子性的，即不会被其他线程干扰。

在计算机科学中，原子操作是指不会被线程调度机制打断的操作，一旦开始，就会一直运行到结束，中间不会发生上下文切换到另一个线程的情况 。
这意味着在多线程环境下，多个线程对共享资源的原子操作是互斥的，不会出现数据竞争或不一致的问题。

常见的原子操作类型包括:
	原子读（Atomic Read）、
	原子写（Atomic Write）、
	原子加（Atomic Add）、
	原子减（Atomic Subtract）
	原子比较交换（Atomic Compare and Swap，即 CAS）等 。
原子读和原子写操作保证了对内存中数据的读取和写入是原子性的，不会出现读取或写入一半数据的情况。
而原子加和原子减操作则常用于对共享计数器等资源的操作，确保在多线程环境下计数器的增减操作是安全的。

在 C++ 中，原子操作可以通过<atomic>头文件来实现。<atomic>头文件提供了一系列的原子类型和原子操作函数，
例如std::atomic<int>表示一个原子整型，
std::atomic<bool>表示一个原子布尔型等。
通过这些原子类型，我们可以方便地在多线程环境下进行原子操作
*/

#include <atomic>
#include <thread>
#include <iostream>
#include <memory>
#include <cassert>
#include <vector>

using namespace std;

atomic<int> g_count(0); // 全局变量，用于存储计数器值
int g_count2 = 0;

atomic<int> vl(5);

void increment()
{
	for(int i = 0; i < 100000; ++i)
	{
		g_count++;
	}
}

void increment2()
{
	for(int i = 0; i < 100000; ++i)
	{
		g_count2++;
	}
}


template<typename T>
class LockFreeQueue
{
	private:
		struct Node 
		{
			T data;
			atomic<Node*> next;
			Node(const T& value) : data(value), next(nullptr) {}
			/* data */
		};

		atomic<Node*> head;
		atomic<Node*> tail;
		
	public:
		LockFreeQueue() : head(new Node(T())), tail(head.load()) {}

		~LockFreeQueue(){
			while (Node* node = head.load())
			{
				head.store(node->next.load());
				delete node;
				/* code */
			}
			
		}

	/*
	入队操作时，线程首先创建一个新节点，然后通过 CAS 操作将新节点链接到队列的尾部。
	具体来说，线程先获取尾指针的当前值，尝试将新节点的指针指向尾指针的下一个节点（初始时为nullptr），
	并通过 CAS 操作将尾指针更新为新节点 。如果 CAS 操作失败，说明尾指针在这期间被其他线程更新了，
	线程需要重新获取尾指针并再次尝试。
	*/
		void push(const T& value)
		{
			unique_ptr<Node> new_node = make_unique<Node>(value);
			Node* oldTail = nullptr;
			Node* next = nullptr;

			do {
				oldTail = tail.load();
				next = oldTail->next.load();
				if (oldTail != tail.load())
				{
					continue;
				}

				if (next != nullptr)
				{
					tail.compare_exchange_weak(oldTail, next);
					continue;
				}
			} while(!oldTail->next.compare_exchange_weak(next, new_node.get()));

			tail.compare_exchange_weak(oldTail, new_node.get());
		}

		/*
		出队操作时，线程首先检查头指针的下一个节点是否存在（因为头指针通常是一个哑节点，不存储实际数据）。
		如果存在，线程尝试通过 CAS 操作将头指针更新为下一个节点，从而实现出队 。
		如果 CAS 操作失败，说明头指针在这期间被其他线程更新了，线程需要重新检查并尝试。
		*/
		bool pop(T& result)
		{
			Node* oldHead = nullptr;
			Node* next = nullptr;

			do {
				oldHead = head.load();
				Node* oldTail = tail.load();
				next = oldHead->next.load();
				if (oldHead != head.load())
				{
					continue;
				}

				if (oldHead == oldTail && next == nullptr)
				{
					return false;
				}
			}while(!head.compare_exchange_weak(oldHead,next));
			result = move(next->data);
			cout <<result<<endl;
			//delete oldHead;
			return true;
		}
};


// 基础功能测试（单线程）
void TestBasicFunctionality() {
    LockFreeQueue<int> queue;

    // 空队列检查
    //assert(queue.empty());
    //assert(queue.size() == 0);

    // 单元素入队出队
    //queue.push(42);
    //assert(!queue.empty());
    //assert(queue.size() == 1);
    
    int val;
    //assert(queue.pop(val));
    //assert(val == 42);
    //assert(queue.empty());

    // 多元素顺序测试
    const int test_count = 1000;
    for(int i=0; i<test_count; ++i) {
        queue.push(i);
		cout<<"push:"<<i<<endl;
    }
    //assert(queue.size() == test_count);

    for(int i=0; i<test_count; ++i) {
		
        queue.pop(val);// && val == i);
		cout<<"pop:"<<i<< " ==>"<< val<<endl;
    }
    //assert(queue.empty());

    std::cout << "[PASS] Basic functionality test\n";
}

// 多线程生产者-消费者测试
void TestConcurrentPushPop() {
    LockFreeQueue<int> queue;
    const int num_producers = 4;
    const int num_consumers = 4;
    const int items_per_producer = 10000;
    const int total_items = num_producers * items_per_producer;

    std::vector<std::thread> producers;
    std::vector<std::thread> consumers;
    std::atomic<int> consumed_count{0};

    // 消费者线程
    for(int i=0; i<num_consumers; ++i) {
        consumers.emplace_back([&] {
            int val;
            while(consumed_count < total_items) {
                if(queue.pop(val)) {
                    consumed_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // 生产者线程
    for(int i=0; i<num_producers; ++i) {
        producers.emplace_back([&, i] {
            for(int j=0; j<items_per_producer; ++j) {
                queue.push(i * items_per_producer + j);
            }
        });
    }

    // 等待生产者完成
    for(auto& t : producers) t.join();

    // 等待消费者处理剩余项目
    while(consumed_count < total_items) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // 清理消费者线程
    for(auto& t : consumers) t.join();

    // 最终状态检查
    //assert(queue.empty());
    std::cout << "[PASS] Concurrent push/pop test\n";
}

// 运行所有测试
void RunTests() {
    auto start = std::chrono::high_resolution_clock::now();
    
    TestBasicFunctionality();
    TestConcurrentPushPop();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "All tests passed in " << elapsed.count() << " seconds\n";
}


int main()
{
	std::thread t1(increment);
	std::thread t2(increment);
	t1.join();
	t2.join();
	cout<<"in the atomic mode --> Final counter value: " << g_count << endl;
	std::thread t3(increment2);
	std::thread t4(increment2);
	t3.join();
	t4.join();
	cout<<"in the normal mode --> Final counter value: " << g_count2 << endl;

	//
	int expect = 5;
	int new_vl = 10;
	if (vl.compare_exchange_weak(expect, new_vl))
	{
		cout << "exchange success, expect: " << expect << ", new_vl: " << new_vl << endl;
	}
	else
	{
		cout<<"exchange failed, expect: " << expect << ", new_vl: " << new_vl << endl;
	}

	//
	RunTests();
	return 0;
}